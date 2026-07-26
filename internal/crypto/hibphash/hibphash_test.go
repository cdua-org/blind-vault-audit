package hibphash

import "testing"

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     string
	}{
		{
			name:     "empty password",
			password: "",
			want:     "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
		},
		{
			name:     "simple password",
			password: "password",
			want:     "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HashPassword(tt.password); got != tt.want {
				t.Errorf("HashPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
