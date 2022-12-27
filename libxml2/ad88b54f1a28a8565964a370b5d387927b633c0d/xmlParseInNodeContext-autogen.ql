/**
 * @name libxml2-ad88b54f1a28a8565964a370b5d387927b633c0d-xmlParseInNodeContext
 * @id cpp/libxml2/ad88b54f1a28a8565964a370b5d387927b633c0d/xmlParseInNodeContext
 * @description libxml2-ad88b54f1a28a8565964a370b5d387927b633c0d-xmlParseInNodeContext CVE-2016-9318
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vctxt_13527, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="input_id"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_13527
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0))
}

predicate func_1(Variable vctxt_13527) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="myDoc"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctxt_13527)
}

from Function func, Variable vctxt_13527
where
not func_0(vctxt_13527, func)
and vctxt_13527.getType().hasName("xmlParserCtxtPtr")
and func_1(vctxt_13527)
and vctxt_13527.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
