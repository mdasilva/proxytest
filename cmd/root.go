// Copyright © 2018 Michael Da Silva madasilva@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var logLevel string
var proxyURL string
var timeout int

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "proxytest",
	Short: "A web proxy tester",
	Long: `A simple cross platform utility to test HTTP GET requests through a web proxy.
See readme.md for additional information.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.app.yaml)")
	rootCmd.PersistentFlags().StringVar(&proxyURL, "proxy-url", os.Getenv("HTTP_PROXY"), "web proxy URL")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "error", "logging level")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 5, "timeout for URL checks")
	viper.BindPFlag("proxy-url", rootCmd.PersistentFlags().Lookup("proxy-url"))
	viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".app" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".app")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
