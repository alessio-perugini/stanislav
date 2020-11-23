package dga

import "testing"

func Test(t *testing.T) {
	LmsScore("")
}

func TestLmsScore(t *testing.T) {
	type args struct {
		subject string
	}
	tests := []struct {
		name string
		args args
		want float64
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{subject: "/quDJa5xQ8bf9um/nKl3/rRPiY6OpgXFX/Ns2bkVRfNXr0/MRh2tGEOHDpyEnsgKE/"},
			want: 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LmsScoreOfDomain(tt.args.subject); got != tt.want {
				t.Errorf("LmsScore() = %v, want %v", got, tt.want)
			}
		})
	}
}

