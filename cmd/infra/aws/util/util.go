package util

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/elb/elbiface"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
	"github.com/bombsimon/logrusr"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
)

var log = logrusr.NewLogger(logrus.New())

func DeleteRecord(ctx context.Context, client route53iface.Route53API, id, recordType, recordName string) error {
	record, err := FindRecord(ctx, client, id, recordType, recordName)
	if err != nil {
		return err
	}

	if record == nil {
		return nil
	}

	// Change batch for deleting
	changeBatch := &route53.ChangeBatch{
		Changes: []*route53.Change{
			{
				Action:            aws.String("DELETE"),
				ResourceRecordSet: record,
			},
		},
	}

	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(id),
		ChangeBatch:  changeBatch,
	}

	_, err = client.ChangeResourceRecordSetsWithContext(ctx, input)
	if err != nil {
		return err
	}
	log.Info("Deleted record", "type", recordType, "name", recordName)
	return err
}

func FindRecord(ctx context.Context, client route53iface.Route53API, id, recordType, name string) (*route53.ResourceRecordSet, error) {
	recordName := fqdn(strings.ToLower(name))
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(id),
		StartRecordName: aws.String(recordName),
		StartRecordType: aws.String(recordType),
		MaxItems:        aws.String("1"),
	}

	var record *route53.ResourceRecordSet
	err := client.ListResourceRecordSetsPagesWithContext(ctx, input, func(resp *route53.ListResourceRecordSetsOutput, lastPage bool) bool {
		if len(resp.ResourceRecordSets) == 0 {
			return false
		}

		recordSet := resp.ResourceRecordSets[0]
		responseName := strings.ToLower(cleanRecordName(*recordSet.Name))
		responseType := strings.ToUpper(*recordSet.Type)

		if recordName != responseName {
			return false
		}
		if recordType != responseType {
			return false
		}

		record = recordSet
		return false
	})

	if err != nil {
		return nil, err
	}
	return record, nil
}

func fqdn(name string) string {
	n := len(name)
	if n == 0 || name[n-1] == '.' {
		return name
	} else {
		return name + "."
	}
}

func cleanRecordName(name string) string {
	str := name
	s, err := strconv.Unquote(`"` + str + `"`)
	if err != nil {
		return str
	}
	return s
}

func LookupZone(client route53iface.Route53API, name string, isPrivateZone bool) (string, error) {
	var res *route53.HostedZone
	f := func(resp *route53.ListHostedZonesOutput, lastPage bool) (shouldContinue bool) {
		for idx, zone := range resp.HostedZones {
			if zone.Config != nil && isPrivateZone == aws.BoolValue(zone.Config.PrivateZone) && strings.TrimSuffix(aws.StringValue(zone.Name), ".") == strings.TrimSuffix(name, ".") {
				res = resp.HostedZones[idx]
				return false
			}
		}
		return !lastPage
	}
	if err := client.ListHostedZonesPages(&route53.ListHostedZonesInput{}, f); err != nil {
		return "", err
	}
	if res == nil {
		return "", fmt.Errorf("hosted zone %s not found", name)
	}
	return strings.TrimPrefix(*res.Id, "/hostedzone/"), nil
}

func VpcFilter(vpcID string) []*ec2.Filter {
	return []*ec2.Filter{
		{
			Name:   aws.String("vpc-id"),
			Values: []*string{aws.String(vpcID)},
		},
	}
}

func DeleteNonDefaultRecords(ctx context.Context, client route53iface.Route53API, zoneID string) error {
	typesToPreserve := sets.NewString("SOA", "NS")

	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	}
	var recordsToDelete []*route53.ResourceRecordSet
	err := client.ListResourceRecordSetsPagesWithContext(ctx, input, func(resp *route53.ListResourceRecordSetsOutput, lastPage bool) bool {
		for i, rrs := range resp.ResourceRecordSets {
			if typesToPreserve.Has(*rrs.Type) {
				continue
			}
			recordsToDelete = append(recordsToDelete, resp.ResourceRecordSets[i])
		}
		return false
	})
	if len(recordsToDelete) == 0 {
		return nil
	}

	// Change batch for deleting
	changeBatch := &route53.ChangeBatch{
		Changes: []*route53.Change{},
	}
	for i, rec := range recordsToDelete {
		changeBatch.Changes = append(changeBatch.Changes, &route53.Change{
			Action:            aws.String("DELETE"),
			ResourceRecordSet: recordsToDelete[i],
		})
		log.Info("Deleting unmanaged record", "zone", zoneID, "name", *rec.Name)
	}

	_, err = client.ChangeResourceRecordSetsWithContext(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch:  changeBatch,
	})
	if err != nil {
		return fmt.Errorf("failed to delete records: %w", err)
	}
	log.Info("Deleted unmanaged non-default records from zone", "zone", zoneID)
	return nil
}

func DeleteUnmanagedELBs(ctx context.Context, client elbiface.ELBAPI, vpcID string) error {
	var errs []error
	deleteLBs := func(out *elb.DescribeLoadBalancersOutput, _ bool) bool {
		for _, lb := range out.LoadBalancerDescriptions {
			if *lb.VPCId != vpcID {
				continue
			}
			tags, err := client.DescribeTags(&elb.DescribeTagsInput{
				LoadBalancerNames: []*string{lb.LoadBalancerName},
			})
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to describe tags for load balancer %s: %w", *lb.LoadBalancerName, err))
				continue
			}
			isManaged := false
			for _, tagDescription := range tags.TagDescriptions {
				for _, tag := range tagDescription.Tags {
					if *tag.Key == "hypershift.openshift.io/infra" && *tag.Value == "owned" {
						isManaged = true
					}
				}
			}
			if isManaged {
				log.Info("Ignoring managed load balancer", "name", *lb.LoadBalancerName, "vpcID", vpcID)
				continue
			}
			_, err = client.DeleteLoadBalancerWithContext(ctx, &elb.DeleteLoadBalancerInput{
				LoadBalancerName: lb.LoadBalancerName,
			})
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to delete load balancer %s: %w", *lb.LoadBalancerName, err))
				continue
			}
			log.Info("Deleted unmanaged load balancer", "name", *lb.LoadBalancerName, "vpcID", vpcID)
		}
		return true
	}
	err := client.DescribeLoadBalancersPagesWithContext(ctx,
		&elb.DescribeLoadBalancersInput{},
		deleteLBs)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete load balancers: %w", err))
	}
	return errors.NewAggregate(errs)
}

func DeleteUnmanagedSecurityGroups(ctx context.Context, client ec2iface.EC2API, vpcID string) error {
	managedGroups := sets.NewString()
	unmanagedGroups := sets.NewString()
	err := client.DescribeSecurityGroupsPagesWithContext(ctx,
		&ec2.DescribeSecurityGroupsInput{Filters: VpcFilter(vpcID)},
		func(out *ec2.DescribeSecurityGroupsOutput, _ bool) bool {
			for _, sg := range out.SecurityGroups {
				if *sg.GroupName == "default" {
					continue
				}
				isManaged := false
				for _, tag := range sg.Tags {
					if *tag.Key == "hypershift.openshift.io/infra" && *tag.Value == "owned" {
						isManaged = true
					}
				}
				if isManaged {
					managedGroups.Insert(*sg.GroupId)
				} else {
					unmanagedGroups.Insert(*sg.GroupId)
				}
			}
			return false
		})
	if err != nil {
		return fmt.Errorf("failed to describe security groups: %w", err)
	}

	var errs []error

	// Revoke all managed group ingress rules that reference unmanaged groups
	// so the unmanaged groups can be deleted
	err = client.DescribeSecurityGroupsPagesWithContext(ctx,
		&ec2.DescribeSecurityGroupsInput{Filters: VpcFilter(vpcID)},
		func(out *ec2.DescribeSecurityGroupsOutput, _ bool) bool {
			for i := range out.SecurityGroups {
				sg := out.SecurityGroups[i]
				if !managedGroups.Has(*sg.GroupId) {
					continue
				}
				var unmanagedPermissions []*ec2.IpPermission
				for _, perm := range sg.IpPermissions {
					for _, pair := range perm.UserIdGroupPairs {
						if !managedGroups.Has(*pair.GroupId) {
							unmanagedPermissions = append(unmanagedPermissions, perm)
							break
						}
					}
				}
				if len(unmanagedPermissions) > 0 {
					_, err := client.RevokeSecurityGroupIngressWithContext(ctx, &ec2.RevokeSecurityGroupIngressInput{
						GroupId:       sg.GroupId,
						IpPermissions: unmanagedPermissions,
					})
					if err != nil {
						errs = append(errs, fmt.Errorf("failed to revoke unmanaged security group ingress from managed group %s: %w", *sg.GroupId, err))
					} else {
						log.Info("Cleaned up unmanaged security group ingress permissions", "id", *sg.GroupId, "permissions", unmanagedPermissions)
					}
				}
			}
			return false
		})
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to revoke security group ingress rules: %w", err))
	}

	// Delete unmanaged security groups
	err = client.DescribeSecurityGroupsPagesWithContext(ctx,
		&ec2.DescribeSecurityGroupsInput{Filters: VpcFilter(vpcID)},
		func(out *ec2.DescribeSecurityGroupsOutput, _ bool) bool {
			for _, sg := range out.SecurityGroups {
				if !unmanagedGroups.Has(*sg.GroupId) {
					continue
				}
				_, err := client.DeleteSecurityGroupWithContext(ctx, &ec2.DeleteSecurityGroupInput{
					GroupId: sg.GroupId,
				})
				if err != nil {
					errs = append(errs, fmt.Errorf("failed to delete security group %s: %w", *sg.GroupId, err))
					continue
				}
				log.Info("Deleted unmanaged security group", "id", *sg.GroupId)
			}
			return true
		})
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete security groups: %w", err))
	}

	return errors.NewAggregate(errs)
}

func NewSession() *session.Session {
	awsSession := session.Must(session.NewSession())
	awsSession.Handlers.Build.PushBackNamed(request.NamedHandler{
		Name: "openshift.io/hypershift",
		Fn:   request.MakeAddToUserAgentHandler("openshift.io hypershift", "cli"),
	})
	return awsSession
}

func NewConfig(credentialsFile, region string) *aws.Config {
	awsConfig := aws.NewConfig().
		WithRegion(region).
		WithCredentials(credentials.NewSharedCredentials(credentialsFile, "default"))
	awsConfig.Retryer = client.DefaultRetryer{
		NumMaxRetries:    3,
		MinRetryDelay:    5 * time.Second,
		MinThrottleDelay: 5 * time.Second,
	}
	return awsConfig
}
