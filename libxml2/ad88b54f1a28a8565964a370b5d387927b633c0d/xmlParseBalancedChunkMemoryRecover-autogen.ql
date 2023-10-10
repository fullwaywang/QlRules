/**
 * @name libxml2-ad88b54f1a28a8565964a370b5d387927b633c0d-xmlParseBalancedChunkMemoryRecover
 * @id cpp/libxml2/ad88b54f1a28a8565964a370b5d387927b633c0d/xmlParseBalancedChunkMemoryRecover
 * @description libxml2-ad88b54f1a28a8565964a370b5d387927b633c0d-xmlParseBalancedChunkMemoryRecover CVE-2016-9318
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vctxt_13761, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="input_id"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_13761
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_0))
}

predicate func_1(Variable vctxt_13761) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="instate"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctxt_13761)
}

from Function func, Variable vctxt_13761
where
not func_0(vctxt_13761, func)
and vctxt_13761.getType().hasName("xmlParserCtxtPtr")
and func_1(vctxt_13761)
and vctxt_13761.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
