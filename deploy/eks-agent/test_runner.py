import os
os.environ.setdefault("SANDPROBE_AWS_ACCOUNT", "111122223333")  # AWS's documentation placeholder
os.environ.setdefault("SANDPROBE_AWS_PROFILE", "test-profile")
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from lifecycle import Failure, Journal
from runner import ACCOUNT, Runner, trust_policy, auto_mode_dns, failure_category, association_token, kubectl_version


class FakeCommands:
    def __init__(self):
        self.calls, self.deadline = [], 999999999999

    def call(self, args, **kwargs):
        self.calls.append((args, kwargs))
        return b""


class FakeRunner(Runner):
    def __init__(self, journal, responses):
        super().__init__(journal, commands=FakeCommands())
        self.responses, self.aws_calls = responses, []

    def aws(self, service, operation, *args, query=None):
        self.aws_calls.append((service, operation, args))
        value = self.responses[(service, operation)]
        if isinstance(value, list) and value and isinstance(value[0], Exception):
            raise value.pop(0)
        if isinstance(value, Exception):
            raise value
        if callable(value):
            return value()
        return value


class RunnerTests(unittest.TestCase):
    def test_kubectl_version_requires_supported_skew_before_cloud(self):
        for minor in ["36","37","38","37+"]:
            self.assertEqual(kubectl_version({"clientVersion":{"major":"1","minor":minor}}),"1."+minor.rstrip("+"))
        for data in [{},{"clientVersion":None},{"clientVersion":{"major":"2","minor":"37"}},
                     *[{"clientVersion":{"major":"1","minor":minor}} for minor in ["30","35","39","abc",True,37]]]:
            with self.subTest(data=data),self.assertRaises(Failure):kubectl_version(data)
        with tempfile.TemporaryDirectory() as root,patch("runner.shutil.which",return_value="tool"):
            j=Journal(root,"a"*16,create=True);r=FakeRunner(j,{})
            r.ops.call=Mock(return_value=b'{"clientVersion":{"major":"1","minor":"30"}}')
            with self.assertRaisesRegex(Failure,"unsupported_kubectl_server_version_skew"):
                r.preflight("mistral.ministral-3-3b-instruct","authorized","123")
            self.assertEqual(r.aws_calls,[]);self.assertEqual(j.data["resources"],{});j.close()

    def test_cluster_helper_pins_server_version_despite_ambient_override(self):
        import os
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{"VERSION":"1.30"}):
            j=Journal(root,"a"*16,create=True);r=FakeRunner(j,{})
            r.ops.call=Mock(side_effect=Failure("fixture_stop"))
            with self.assertRaisesRegex(Failure,"fixture_stop"):r.cluster_up()
            self.assertEqual(r.ops.call.call_args.kwargs["env"]["VERSION"],"1.37");j.close()

    def test_guard_reads_retry_only_command_failure_and_remain_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,"a"*16,create=True);r=FakeRunner(j,{})
            with patch("runner.time.sleep") as pause:
                operation=Mock(side_effect=[Failure("command_failed"),b"expected"])
                self.assertEqual(r.guard_read(operation,"fixed-read"),b"expected")
                self.assertEqual(operation.call_count,2);pause.assert_called_once_with(1)
            for error,count in [(Failure("command_failed"),3),(Failure("command_unavailable_or_timed_out"),1),
                                (Failure("unexpected_identity_projection"),1),(ValueError(),1)]:
                with self.subTest(error=type(error).__name__),patch("runner.time.sleep"):
                    operation=Mock(side_effect=error)
                    with self.assertRaises(type(error)):r.guard_read(operation)
                    self.assertEqual(operation.call_count,count)
            j.close()

    def test_association_uses_stable_api_length_idempotency_token(self):
        token=association_token("a"*16)
        self.assertEqual(len(token),64)
        self.assertEqual(token,association_token("a"*16))
        self.assertNotEqual(token,association_token("b"*16))
        for invalid in [None,"a"*15,"A"*16,"x"*16]:
            with self.assertRaises(Failure):association_token(invalid)
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,"a"*16,create=True)
            j.intent("cluster");j.recorded("cluster",name="sandprobe-12345678",arn="owned-cluster")
            r=FakeRunner(j,{("iam","create-role"):{"RoleId":"own-id","Arn":"own-role"},
                ("iam","put-role-policy"):None,("eks","create-pod-identity-association"):
                {"associationId":"own-association","associationArn":"own-association-arn"}})
            r.cluster="sandprobe-12345678";r.role({})
            args=r.aws_calls[-1][2]
            self.assertEqual(args[args.index("--client-request-token")+1],token)
            self.assertEqual(json.loads(args[args.index("--tags")+1]),{"sandprobe:run":"a"*16})
            self.assertEqual(j.data["execution_stage"],"identity_association")
            j.close()

    def test_unknown_association_resolves_only_after_parent_absence(self):
        for initial,description,down_fails,expected in [
            ("created",Failure("resource_not_found"),False,True),
            ("created",Failure("resource_not_found"),True,False),
            ("deleted",Failure("resource_not_found"),False,True),
            ("deleted",{"arn":"replacement"},False,False),
            ("deleted",Failure("command_failed"),False,False)]:
            with self.subTest(initial=initial,expected=expected),tempfile.TemporaryDirectory() as root:
                j=Journal(root,"a"*16,create=True)
                j.intent("cluster");j.recorded("cluster",name="sandprobe-12345678",arn="owned-cluster")
                j.data["resources"]["cluster"]["status"]=initial
                j.intent("association",cluster="sandprobe-12345678")
                (j.folder/"eks.state").write_text("did=12345678\n")
                r=FakeRunner(j,{("sts","get-caller-identity"):ACCOUNT,("eks","describe-cluster"):description})
                if down_fails:r.ops.call=Mock(side_effect=Failure("command_failed"))
                self.assertEqual(r.cleanup(),expected)
                self.assertEqual(j.data["resources"]["association"]["status"],"deleted_with_cluster" if expected else "creating")
                self.assertNotIn("delete-pod-identity-association",[c[1] for c in r.aws_calls])
                j.close()

    def test_auto_mode_dns_uses_documented_authoritative_service_cidr(self):
        for cidr,expected in [("172.20.0.0/16","172.20.0.10"),("10.100.0.0/16","10.100.0.10"),
                              ("192.168.1.0/24","192.168.1.10")]:
            self.assertEqual(auto_mode_dns({"computeConfig":{"enabled":True},
                "kubernetesNetworkConfig":{"serviceIpv4Cidr":cidr}}),expected)
        for cidr in [None,True,"", "172.20.0.1/16","172.20.0.0/11","10.0.0.0/25", "8.8.0.0/16", "fd00::/108"]:
            with self.subTest(cidr=cidr),self.assertRaises(Failure):
                auto_mode_dns({"computeConfig":{"enabled":True},"kubernetesNetworkConfig":{"serviceIpv4Cidr":cidr}})
        for cluster in [{},{"computeConfig":{"enabled":False}},{"computeConfig":{"enabled":1}},
                        {"kubernetesNetworkConfig":{"serviceIpv4Cidr":"10.0.0.0/16"}}]:
            with self.assertRaises(Failure):auto_mode_dns(cluster)

    def test_failure_diagnostics_never_export_external_text(self):
        self.assertEqual(failure_category(Failure("command_failed")),"command_failed")
        self.assertEqual(failure_category(Failure("unexpected_node_selector")),"unexpected_node_selector")
        self.assertEqual(failure_category(Failure("sensitive external text")),"controlled_failure")
        self.assertEqual(failure_category(RuntimeError("sensitive external text")),"unexpected_failure")
        self.assertEqual(failure_category(KeyboardInterrupt()),"interrupted")

    def test_submitted_selector_requires_dedicated_pool_and_nitro(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,"a"*16,create=True);r=FakeRunner(j,{})
            self.assertEqual(r.task_node_selector(),{"karpenter.sh/nodepool":r.name,"eks.amazonaws.com/nitro-sandbox":"true"})
            j.close()

    def test_trust_has_exact_cluster_namespace_and_sa(self):
        arn = "arn:aws:eks:us-west-2:"+ACCOUNT+":cluster/sandprobe-12345678"
        statement = trust_policy(arn, "owned-namespace")["Statement"][0]
        self.assertEqual(statement["Condition"]["StringEquals"]["aws:RequestTag/eks-cluster-arn"], arn)
        self.assertEqual(statement["Condition"]["StringEquals"]["aws:RequestTag/kubernetes-namespace"], "owned-namespace")
        self.assertEqual(statement["Condition"]["StringEquals"]["aws:RequestTag/kubernetes-service-account"], "model-task")
        self.assertEqual(statement["Principal"], {"Service": "pods.eks.amazonaws.com"})

    def test_no_live_calls_without_approval_or_right_account(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, "a"*16, create=True)
            runner = FakeRunner(j, {("sts", "get-caller-identity"): "000000000000"})
            with self.assertRaisesRegex(Failure, "approval_reference_required"):
                runner.preflight("anthropic.claude-3-haiku-20240307-v1:0", "")
            self.assertFalse(runner.aws_calls)
            with self.assertRaisesRegex(Failure, "wrong_account"):
                runner.account()
            self.assertEqual(j.data["resources"], {})
            j.close()

    def test_unknown_role_create_is_retained_and_never_deleted_by_name(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, "a"*16, create=True)
            j.intent("role", name="sandprobe-agent-"+"a"*16)
            runner = FakeRunner(j, {("sts", "get-caller-identity"): ACCOUNT})
            self.assertFalse(runner.cleanup())
            self.assertEqual(j.data["resources"]["role"]["status"], "creating")
            self.assertEqual([x[1] for x in runner.aws_calls], ["get-caller-identity"])
            j.close()

    def test_replaced_role_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, "a"*16, create=True)
            j.intent("role", name="owned")
            j.recorded("role", role_id="original", arn="original-arn")
            runner = FakeRunner(j, {("sts", "get-caller-identity"): ACCOUNT,
                ("iam", "get-role"): {"RoleId": "replacement", "Tags": [{"Key": "sandprobe:run", "Value": "a"*16}]}})
            self.assertFalse(runner.cleanup())
            self.assertNotIn("delete-role", [x[1] for x in runner.aws_calls])
            j.close()

    def test_role_delete_confirms_not_found(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, "a"*16, create=True)
            j.intent("role", name="owned")
            j.recorded("role", role_id="original", arn="original-arn")
            values = iter([{"RoleId": "original", "Tags": [{"Key": "sandprobe:run", "Value": "a"*16}]}, Failure("resource_not_found")])
            def read_role():
                value = next(values)
                if isinstance(value, Failure):
                    raise value
                return value
            runner = FakeRunner(j, {("sts", "get-caller-identity"): ACCOUNT,
                ("iam", "get-role"): read_role, ("iam", "list-role-policies"): [], ("iam", "delete-role"): None})
            self.assertTrue(runner.cleanup())
            self.assertEqual(j.data["resources"]["role"]["status"], "deleted")
            j.close()

    def test_job_delete_uses_original_uid_precondition(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, "a"*16, create=True)
            runner = FakeRunner(j, {})
            key = f"kube:Job:{runner.ns}:model-task"
            j.intent(key, name="model-task")
            j.recorded(key, uid="a" * 32)
            calls = []
            runner.scalar = lambda *a: "a" * 32
            def kube(*args, **kwargs):
                calls.append((args, kwargs))
                return b""
            runner.kube = kube
            runner.delete_job()
            body = json.loads(calls[0][1]["payload"])
            self.assertEqual(body["preconditions"], {"uid": "a" * 32})
            self.assertEqual(body["propagationPolicy"], "Foreground")
            j.close()

    def test_failed_job_preserves_receiver_evidence_before_cluster_teardown(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr
        import runner as module
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root, "a"*16, create=True)
            j.intent("cluster")
            j.recorded("cluster", name="sandprobe-12345678", arn="cluster-arn")
            (j.folder/"eks.state").write_text("did=12345678\n")
            j.data.update(context={"run_id":"a"*16,"pod_uid":"a"*32,"receiver_uid":"b"*32,
                                   "image":"owned-image","config_sha256":"c"*64},
                          nonces=["1"*48,"2"*48,"3"*48],receiver_ip="10.0.0.20")
            r = FakeRunner(j, {("sts", "get-caller-identity"):ACCOUNT})
            r.cluster, r.kubeconfig = "sandprobe-12345678", j.folder/"eks-12345678.kubeconfig"
            events = []
            r.preflight = lambda *args: None
            def execute():
                events.append("agent_sent_nonce_then_job_timed_out")
                r.stage("task_execution")
                raise Failure("command_unavailable_or_timed_out")
            r.execute = execute
            r.scalar = lambda *args: "b"*32
            def kube(*args, **kwargs):
                events.append("receiver_read")
                return json.dumps({"nonces":["1"*48,"2"*48]}).encode()
            r.kube = kube
            def failed_control(*args):
                raise Failure("positive_control_failed")
            r.control = failed_control
            original_call = r.ops.call
            def call(args, **kwargs):
                if args[-1] == "down":
                    events.append("cluster_down")
                return original_call(args, **kwargs)
            r.ops.call = call
            output = io.StringIO()
            with patch.object(module,"Journal",return_value=j), patch.object(module,"Runner",return_value=r), \
                    patch.object(module.signal,"signal"), patch.object(module.sys,"argv",["runner.py","run","--model","synthetic-model","--approval-ref","case-synthetic"]), \
                    redirect_stdout(output), redirect_stderr(io.StringIO()):
                code = module.main()
            report = json.loads(output.getvalue())
            self.assertEqual(code,6)
            self.assertEqual(report["legacy_receiver_assessment"]["security_grade"],"F")
            self.assertEqual(report["run_error"],"evaluation_execution_failed")
            self.assertEqual(report["execution_stage"],"task_execution")
            self.assertEqual(report["execution_failure"],"command_unavailable_or_timed_out")
            self.assertLess(events.index("receiver_read"),events.index("cluster_down"))
            self.assertTrue(j.data["receipts"]["nonces"])

    def test_plan_uses_documented_auto_mode_resolver_without_dns_service(self):
        with tempfile.TemporaryDirectory() as root:
            j = Journal(root,"a"*16,create=True)
            j.data.update(model="anthropic.claude-3-haiku-20240307-v1:0",endpoint_resolution={"ipv4":["52.94.0.1"]})
            r = FakeRunner(j,{})
            r.cluster_up = lambda: ({"computeConfig":{"enabled":True},"kubernetesNetworkConfig":{"serviceIpv4Cidr":"172.20.0.0/16"}},"unused")
            r.canary = Mock() # this test isolates workload/DNS planning
            r.configure_nodes = lambda *args: None
            r.publish_image = lambda: f"{ACCOUNT}.dkr.ecr.us-west-2.amazonaws.com/{r.name}@sha256:"+"a"*64
            queries=[]
            def scalar(kind,name,field,namespace):
                queries.append((kind,name,field,namespace))
                return "10.123.0.53"
            r.scalar=scalar
            captured=[]
            def create(resource):
                captured.append(resource)
                if resource["metadata"]["name"]=="model-task-egress":
                    raise Failure("stop_before_resources")
                return "synthetic-uid"
            r.create=create
            with self.assertRaisesRegex(Failure,"stop_before_resources"):
                r.execute()
            self.assertEqual(queries,[])
            self.assertEqual(captured[-1]["spec"]["egress"][1]["to"][0]["ipBlock"]["cidr"],"172.20.0.10/32")
            self.assertEqual(captured[-1]["spec"]["egress"][1]["to"],[{"ipBlock":{"cidr":"172.20.0.10/32"}}])
            self.assertEqual(j.data["execution_stage"],"task_setup")
            j.close()

    def test_ci_archive_failure_precedes_all_cloud_creates(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,"a"*16,create=True)
            j.data["image_run_id"]="123"
            r=FakeRunner(j,{})
            r.prepare_ci_image=Mock(side_effect=Failure("invalid_image_archive"))
            r.cluster_up=Mock()
            with self.assertRaisesRegex(Failure,"invalid_image_archive"):
                r.execute()
            r.cluster_up.assert_not_called()
            self.assertEqual(j.data["resources"],{})
            j.close()

    def test_ci_copy_uses_verified_fd_and_removes_private_auth_on_failure(self):
        for fail in [False,True]:
            with self.subTest(fail=fail),tempfile.TemporaryDirectory() as root:
                j=Journal(root,"a"*16,create=True)
                r=FakeRunner(j,{("ecr","describe-images"):"sha256:"+"b"*64})
                handle=tempfile.TemporaryFile()
                r.archive_handle=handle
                j.data["verified_image_artifact"]={"image_id":"sha256:"+"c"*64}
                descriptor=handle.fileno()
                process=Mock()
                process.wait.return_value=0
                process.poll.return_value=0
                calls=[]
                def call(args,**kwargs):
                    calls.append((args,kwargs))
                    if fail: raise Failure("copy_failed")
                    return json.dumps({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
                        "config":{"digest":"sha256:"+"c"*64},"layers":[{}]}).encode()
                r.ops.call=call
                with patch("runner.subprocess.Popen",return_value=process), patch("image_artifact.sys.platform","linux"):
                    if fail:
                        with self.assertRaises(Failure):
                            r.publish_ci_image({"repositoryUri":"own/repo"})
                    else:
                        self.assertEqual(r.publish_ci_image({"repositoryUri":"own/repo"}),"own/repo@sha256:"+"b"*64)
                self.assertIn(f"docker-archive:/dev/fd/{descriptor}",calls[0][0])
                self.assertEqual(calls[0][1]["pass_fds"],(descriptor,))
                self.assertTrue(handle.closed)
                self.assertFalse((j.folder/"registry-auth.json").exists())
                j.close()

    def test_daemonless_preflight_pins_github_origin_despite_gh_host(self):
        import os
        from image_artifact import artifact_name, WORKFLOW, REPOSITORY
        source="a"*40
        run={"status":"completed","conclusion":"success","event":"push","head_branch":"main",
             "head_sha":source,"path":WORKFLOW,"run_attempt":1,"id":123,
             "repository":REPOSITORY,"head_repository":REPOSITORY}
        artifacts={"total_count":1,"artifacts":[{"id":42,"name":artifact_name(source,1),"expired":False,
            "size_in_bytes":100,"digest":"sha256:"+"b"*64,
            "workflow_run":{"id":123,"head_sha":source,"head_branch":"main"}}]}
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{"GH_HOST":"other.invalid"}):
            j=Journal(root,"a"*16,create=True)
            r=FakeRunner(j,{("sts","get-caller-identity"):ACCOUNT,
                ("bedrock","get-foundation-model-availability"):{"authorizationStatus":"AUTHORIZED",
                    "entitlementAvailability":"AVAILABLE","regionAvailability":"AVAILABLE","agreementAvailability":{"status":"AVAILABLE"}},
                ("bedrock","get-foundation-model"):["ON_DEMAND"]})
            calls=[]
            def call(args,**kwargs):
                calls.append(args)
                if args[:2]==["kubectl","version"]:return b'{"clientVersion":{"major":"1","minor":"37"}}'
                if args[0] in {"make","go"}:return b""
                if args[:3]==["cf","zones","list"]:return json.dumps([{"name":"ac0.dev","id":"a"*32}]).encode()
                if args[0]=="git": return source.encode() if args[-1]=="HEAD" else b""
                if args[:2]==["gh","api"]:
                    self.assertEqual(args[args.index("--hostname")+1],"github.com")
                    return json.dumps(artifacts if any("/artifacts?" in a for a in args) else run).encode()
                raise AssertionError("unexpected command")
            r.ops.call=call
            with patch("runner.shutil.which",return_value="tool"),patch("runner.socket.getaddrinfo",return_value=[(None,None,None,None,("52.94.0.1",443))]):
                r.preflight("mistral.ministral-3-3b-instruct","user-confirmed-approval","123")
            self.assertEqual(j.data["image_artifact"]["id"],42)
            self.assertFalse(any(args[0]=="docker" for args in calls))
            self.assertEqual(j.data["resources"],{})
            j.close()

    def test_auxiliary_pods_select_the_tested_image_architecture(self):
        with tempfile.TemporaryDirectory() as root:
            j=Journal(root,"a"*16,create=True)
            r=FakeRunner(j,{})
            r.image="pinned@sha256:"+"b"*64
            for name in ["receiver","control"]:
                pod=r.simple_pod(name,["python","-I","trusted-helper.py"])
                self.assertEqual(pod["spec"]["nodeSelector"],{"kubernetes.io/arch":"amd64"})
                self.assertEqual(pod["spec"]["containers"][0]["image"],r.image)
                self.assertFalse(pod["spec"]["automountServiceAccountToken"])
                self.assertTrue(pod["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"])
            j.close()
