/**
 * @name libxml2-5930fe01963136ab92125feec0c6204d9c9225dc-xmlCtxtReset
 * @id cpp/libxml2/5930fe01963136ab92125feec0c6204d9c9225dc/xmlCtxtReset
 * @description libxml2-5930fe01963136ab92125feec0c6204d9c9225dc-parser.c-xmlCtxtReset CVE-2022-2309
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_14792, ExprStmt target_1, LogicalAndExpr target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nsNr"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_14792
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_14792, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_14792
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_2(Parameter vctxt_14792, LogicalAndExpr target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_14792
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("xmlDictPtr")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlDictPtr")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="version"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_14792
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vctxt_14792, ExprStmt target_1, LogicalAndExpr target_2
where
not func_0(vctxt_14792, target_1, target_2, func)
and func_1(vctxt_14792, target_1)
and func_2(vctxt_14792, target_2)
and vctxt_14792.getType().hasName("xmlParserCtxtPtr")
and vctxt_14792.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
