/**
 * @name libxml2-23f05e0c33987d6605387b300c4be5da2120a7ab-xmlInitParserCtxt
 * @id cpp/libxml2/23f05e0c33987d6605387b300c4be5da2120a7ab/xmlInitParserCtxt
 * @description libxml2-23f05e0c33987d6605387b300c4be5da2120a7ab-parserInternals.c-xmlInitParserCtxt CVE-2013-0338
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_1564, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentities"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_1564
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(65)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(65).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_1564, ExprStmt target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_1564
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(66)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(66).getFollowingStmt()=target_1)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vctxt_1564, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nbentities"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_1564
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Parameter vctxt_1564, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="input_id"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_1564
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vctxt_1564, ExprStmt target_2, ExprStmt target_3
where
not func_0(vctxt_1564, target_2, func)
and not func_1(vctxt_1564, target_3, func)
and func_2(vctxt_1564, target_2)
and func_3(vctxt_1564, target_3)
and vctxt_1564.getType().hasName("xmlParserCtxtPtr")
and vctxt_1564.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
