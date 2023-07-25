/**
 * @name curl-57d299a499155d4b327e341c6024e293b0418243-Curl_ntlm_core_mk_nt_hash
 * @id cpp/curl/57d299a499155d4b327e341c6024e293b0418243/Curl-ntlm-core-mk-nt-hash
 * @description curl-57d299a499155d4b327e341c6024e293b0418243-lib/curl_ntlm_core.c-Curl_ntlm_core_mk_nt_hash CVE-2018-14618
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_559, MulExpr target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_559
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="9223372036854775807"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_4.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vpw_560, NotExpr target_6, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpw_560
		and target_1.getExpr().(AssignExpr).getRValue() instanceof ConditionalExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlen_559, Variable vCurl_cmalloc, Variable vCurl_cstrdup, ConditionalExpr target_2) {
		target_2.getCondition().(VariableAccess).getTarget()=vlen_559
		and target_2.getThen().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cmalloc
		and target_2.getThen().(VariableCall).getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_559
		and target_2.getThen().(VariableCall).getArgument(0).(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getElse().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_2.getElse().(VariableCall).getArgument(0).(StringLiteral).getValue()=""
}

predicate func_3(Function func, Initializer target_3) {
		target_3.getExpr() instanceof ConditionalExpr
		and target_3.getExpr().getEnclosingFunction() = func
}

predicate func_4(Variable vlen_559, MulExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vlen_559
		and target_4.getRightOperand().(Literal).getValue()="2"
}

predicate func_5(Variable vlen_559, Variable vpw_560, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("ascii_to_unicode_le")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpw_560
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_559
}

predicate func_6(Variable vpw_560, NotExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vpw_560
}

from Function func, Variable vlen_559, Variable vpw_560, Variable vCurl_cmalloc, Variable vCurl_cstrdup, ConditionalExpr target_2, Initializer target_3, MulExpr target_4, ExprStmt target_5, NotExpr target_6
where
not func_0(vlen_559, target_4, target_5, func)
and not func_1(vpw_560, target_6, func)
and func_2(vlen_559, vCurl_cmalloc, vCurl_cstrdup, target_2)
and func_3(func, target_3)
and func_4(vlen_559, target_4)
and func_5(vlen_559, vpw_560, target_5)
and func_6(vpw_560, target_6)
and vlen_559.getType().hasName("size_t")
and vpw_560.getType().hasName("unsigned char *")
and vCurl_cmalloc.getType().hasName("curl_malloc_callback")
and vCurl_cstrdup.getType().hasName("curl_strdup_callback")
and vlen_559.getParentScope+() = func
and vpw_560.getParentScope+() = func
and not vCurl_cmalloc.getParentScope+() = func
and not vCurl_cstrdup.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
