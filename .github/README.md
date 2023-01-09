### Apache SpamAssassin
#### GitHub Actions for testing

The [Apache SpamAssassin project](https://spamassassin.apache.org/ "Apache SpamAssassin project") uses a [subversion repo](https://svn.apache.org/repos/asf/spamassassin/ "subversion repo") for its development process. A read-only mirror of the repo is maintained on GitHub [here](https://github.com/apache/spamassassin "here").

The .github directory containing this README file is not part of the Apache SpamAssassin release package. The files in this directory are intended for use by developers to run tests using GitHub's Actions facility on GitHub hosted runners.

The Apache SpamAssassin Project Management Committe has not made any arrangements to use the resources allocated to the Apache Software Foundation by GitHub to run builds and tests. The actions defined in this directory are available for anyone, including active developers of SpamAssassin, to run in their personal GitHub fork of the repo. However, the inclusion of the files in this repository does not comprise a formal release of the software to the public.

#### How to use

- Fork this repo to your own GitHub repo
- Usually the default settings for the repo will allow you to run actions. If not, see [Managing GitHub Actions]( https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository "Managing GitHub Actions").
- Click on the **Actions** tab
- Click on **SpamAssassin make test** in the left sidebar
- Click on the **Run workflow** dropdown button on the right of the page
- Edit the four input boxes in the dropdown to select those options that you want to run. Make sure that you follow the syntax of the options as shown, i.e., keep the square braces, use quotes and commas where the dropdown already does.
- Click the **Run workflow** button to submit the jobs
- Click the **Actions** tab to refresh the screen and show the submitted workflow run, then click the entry for the run you just submitted to see the jobs that are included in it, displayed in the left sidebar.

The workflow run you submit will have one job for every valid combination of values from the first three input boxes.

The fourth input box allows you to enter the tests to be run, im the same format as used for TEST_FILES in a make test command line. If left empty, it means run all tests.

No matter what is entered in the tests box, the tests that use SQL will only be run in the jobs that have postgres or mysql specified for database. Also, the spamd stress tests and root tests are never run.

GitHub has limits on number of jobs you can run simultaneously on the various platforms. Jobs you submit that are over that limit will be queued to be started as other jobs finish.

Clicking on a job listed in the left sidebar will open a pane showing the log output of the job. A job that ends with errors will have a red X icon. You can check the log output for details. Some errors will result in the t/log directory contents being zipped up as an artifact you can download. When you are viewing the log pane, click on the **Summary** icon above the left sidebar, If there are any artifacts to download, there will be a number you can click on under the heading **Artifacts**.

#### Notes

The number of jobs run is the product of the options you specify in the three input boxes. Unless you want to test SpamAssassin on every possible version of perl, which you might if you are the release manager preparing a new release, you will likely want to select only one recent version of perl.

The options box for runners only shows the "-latest" names, but you can enter any GitHub hosted runner that they make available, e.g. ubuntu-20.04 or macos-11.

Windows is tested using Strawberry Perl, of which the latest release is 5.32. If you have 34 or 36 in the perl versions list, they will not generate jobs on the Windows platform.

Jobs run using the database option postgres or mysql will only run the various sql tests. Jobs run using the none option for database will run all the other tests.

Some tests, especially some that rely on network access such as t/dnsbl.t, seem to fail occassionally, especially when you are running many jobs simultaneously. After all the jobs of a workflow have completed, you can rerun just those that have failed by clicking on the **Re-run jobs** button in the overview page for the jobs, and then selecting **Re-run failed jobs**. Repeat until jobs that seem to be only intermittent failures have successfully passed.
