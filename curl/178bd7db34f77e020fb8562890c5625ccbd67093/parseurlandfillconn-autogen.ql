/**
 * @name curl-178bd7db34f77e020fb8562890c5625ccbd67093-parseurlandfillconn
 * @id cpp/curl/178bd7db34f77e020fb8562890c5625ccbd67093/parseurlandfillconn
 * @description curl-178bd7db34f77e020fb8562890c5625ccbd67093-lib/url.c-parseurlandfillconn CVE-2014-8150
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_3827, ValueFieldAccess target_1, ValueFieldAccess target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("strpbrk")
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="url"
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="change"
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3827
		and target_0.getCondition().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\r\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_3827
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Illegal characters found in URL"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_3827, ValueFieldAccess target_1) {
		target_1.getTarget().getName()="path"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3827
}

predicate func_2(Parameter vdata_3827, ValueFieldAccess target_2) {
		target_2.getTarget().getName()="url"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="change"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3827
}

from Function func, Parameter vdata_3827, ValueFieldAccess target_1, ValueFieldAccess target_2
where
not func_0(vdata_3827, target_1, target_2, func)
and func_1(vdata_3827, target_1)
and func_2(vdata_3827, target_2)
and vdata_3827.getType().hasName("SessionHandle *")
and vdata_3827.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
