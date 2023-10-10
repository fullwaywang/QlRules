/**
 * @name linux-8c39e2699f8acb2e29782a834e56306da24937fe-chap_server_compute_md5
 * @id cpp/linux/8c39e2699f8acb2e29782a834e56306da24937fe/chap_server_compute_md5
 * @description linux-8c39e2699f8acb2e29782a834e56306da24937fe-chap_server_compute_md5 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vresponse_176, Variable vserver_digest_180) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("bin2hex")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vresponse_176
		and target_0.getArgument(1).(VariableAccess).getTarget()=vserver_digest_180
		and target_0.getArgument(2) instanceof Literal)
}

predicate func_1(Variable vdigest_175, Variable vresponse_176) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("bin2hex")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vresponse_176
		and target_1.getArgument(1).(VariableAccess).getTarget()=vdigest_175
		and target_1.getArgument(2) instanceof Literal)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="16"
		and target_4.getEnclosingFunction() = func)
}

predicate func_8(Variable vresponse_176, Variable vserver_digest_180) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("chap_binaryhex_to_asciihex")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vresponse_176
		and target_8.getArgument(1).(VariableAccess).getTarget()=vserver_digest_180
		and target_8.getArgument(2) instanceof Literal)
}

predicate func_9(Variable vdigest_175, Variable vresponse_176) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("chap_binaryhex_to_asciihex")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vresponse_176
		and target_9.getArgument(1).(VariableAccess).getTarget()=vdigest_175
		and target_9.getArgument(2) instanceof Literal)
}

from Function func, Variable vdigest_175, Variable vresponse_176, Variable vserver_digest_180
where
not func_0(vresponse_176, vserver_digest_180)
and not func_1(vdigest_175, vresponse_176)
and func_4(func)
and func_8(vresponse_176, vserver_digest_180)
and func_9(vdigest_175, vresponse_176)
and vdigest_175.getType().hasName("unsigned char[16]")
and vresponse_176.getType().hasName("unsigned char[34]")
and vserver_digest_180.getType().hasName("unsigned char[16]")
and vdigest_175.getParentScope+() = func
and vresponse_176.getParentScope+() = func
and vserver_digest_180.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
