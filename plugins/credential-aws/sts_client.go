package credentialaws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// STSClient abstracts the AWS STS operations used by this plugin.
type STSClient interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// newRealSTSClient creates a real AWS STS client using static credentials.
func newRealSTSClient(accessKeyID, secretAccessKey, region, endpoint string) STSClient {
	opts := func(o *sts.Options) {
		o.Region = region
		o.Credentials = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
			accessKeyID, secretAccessKey, "",
		))
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	}
	return sts.New(sts.Options{}, opts)
}

// fakeSTSClient is used in tests.
type fakeSTSClient struct {
	assumeRoleFunc        func(ctx context.Context, params *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	getCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
}

func (f *fakeSTSClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if f.assumeRoleFunc != nil {
		return f.assumeRoleFunc(ctx, params)
	}
	now := time.Now()
	expiration := now.Add(time.Duration(*params.DurationSeconds) * time.Second)
	return &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIAFAKEKEY123456789"),
			SecretAccessKey: aws.String("fakesecretaccesskey1234567890abcdef"),
			SessionToken:    aws.String("FakeSessionToken/very-long-string"),
			Expiration:      &expiration,
		},
		AssumedRoleUser: &ststypes.AssumedRoleUser{
			Arn:           aws.String("arn:aws:sts::123456789012:assumed-role/test-role/session"),
			AssumedRoleId: aws.String("AROAFAKEID:session"),
		},
	}, nil
}

func (f *fakeSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.getCallerIdentityFunc != nil {
		return f.getCallerIdentityFunc(ctx, params)
	}
	return &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"),
		Arn:     aws.String("arn:aws:iam::123456789012:user/minter"),
		UserId:  aws.String("AIDAFAKEID123456789"),
	}, nil
}
