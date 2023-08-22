/**
 * @name curl-076a2f629119222aeeb50f5a03bf9f9052fabb9a-Curl_close
 * @id cpp/curl/076a2f629119222aeeb50f5a03bf9f9052fabb9a/Curl-close
 * @description curl-076a2f629119222aeeb50f5a03bf9f9052fabb9a-lib/url.c-Curl_close CVE-2023-23914
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdata_372, ArrayExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="share"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_372
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_372
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_0)
		and target_3.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdata_372, AddressOfExpr target_4, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("curl_slist_free_all")
		and target_1.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hstslist"
		and target_1.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_1.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_372
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_1)
		and target_1.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vdata_372, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("Curl_hsts_cleanup")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_372
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vdata_372, ArrayExpr target_3) {
		target_3.getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_3.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_372
}

predicate func_4(Variable vdata_372, AddressOfExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_372
}

from Function func, Variable vdata_372, ExprStmt target_2, ArrayExpr target_3, AddressOfExpr target_4
where
not func_0(vdata_372, target_3, func)
and not func_1(vdata_372, target_4, func)
and func_2(vdata_372, func, target_2)
and func_3(vdata_372, target_3)
and func_4(vdata_372, target_4)
and vdata_372.getType().hasName("Curl_easy *")
and vdata_372.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
