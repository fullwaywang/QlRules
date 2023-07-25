/**
 * @name curl-50c9484278c63b958655a717844f0721263939cc-Curl_auth_create_ntlm_type3_message
 * @id cpp/curl/50c9484278c63b958655a717844f0721263939cc/Curl-auth-create-ntlm-type3-message
 * @description curl-50c9484278c63b958655a717844f0721263939cc-Curl_auth_create_ntlm_type3_message CVE-2019-3822
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Function func) {
	exists(DoStmt target_3 |
		target_3.getCondition().(Literal).getValue()="0"
		and target_3.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vsize_519, Variable vntlmbuf_520, Variable vntresplen_525, Variable vptr_ntresp_527) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vntlmbuf_520
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsize_519
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vptr_ntresp_527
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vntresplen_525
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation)
}

predicate func_5(Variable vsize_519, Variable vntresplen_525) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vsize_519
		and target_5.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vntresplen_525
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation)
}

predicate func_8(Variable vsize_519, Variable vntresplen_525) {
	exists(RelationalOperation target_8 |
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vsize_519
		and target_8.getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_8.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vntresplen_525
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof DoStmt
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt)
}

predicate func_9(Parameter vdata_493, Parameter vpasswdp_495, Variable vlmbuffer_646) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("Curl_ntlm_core_mk_lm_hash")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vdata_493
		and target_9.getArgument(1).(VariableAccess).getTarget()=vpasswdp_495
		and target_9.getArgument(2).(VariableAccess).getTarget()=vlmbuffer_646)
}

from Function func, Parameter vdata_493, Parameter vpasswdp_495, Variable vsize_519, Variable vntlmbuf_520, Variable vntresplen_525, Variable vptr_ntresp_527, Variable vlmbuffer_646
where
func_3(func)
and func_4(vsize_519, vntlmbuf_520, vntresplen_525, vptr_ntresp_527)
and func_5(vsize_519, vntresplen_525)
and func_8(vsize_519, vntresplen_525)
and vdata_493.getType().hasName("Curl_easy *")
and func_9(vdata_493, vpasswdp_495, vlmbuffer_646)
and vpasswdp_495.getType().hasName("const char *")
and vsize_519.getType().hasName("size_t")
and vntlmbuf_520.getType().hasName("unsigned char[1024]")
and vntresplen_525.getType().hasName("unsigned int")
and vptr_ntresp_527.getType().hasName("unsigned char *")
and vlmbuffer_646.getType().hasName("unsigned char[24]")
and vdata_493.getParentScope+() = func
and vpasswdp_495.getParentScope+() = func
and vsize_519.getParentScope+() = func
and vntlmbuf_520.getParentScope+() = func
and vntresplen_525.getParentScope+() = func
and vptr_ntresp_527.getParentScope+() = func
and vlmbuffer_646.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
