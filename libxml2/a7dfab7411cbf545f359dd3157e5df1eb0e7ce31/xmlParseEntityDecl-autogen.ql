/**
 * @name libxml2-a7dfab7411cbf545f359dd3157e5df1eb0e7ce31-xmlParseEntityDecl
 * @id cpp/libxml2/a7dfab7411cbf545f359dd3157e5df1eb0e7ce31/xmlParseEntityDecl
 * @description libxml2-a7dfab7411cbf545f359dd3157e5df1eb0e7ce31-parser.c-xmlParseEntityDecl CVE-2015-7941
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_5453, EqualityOperation target_1, ExprStmt target_2, EqualityOperation target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlStopParser")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_5453
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_5453, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_5453
		and target_1.getAnOperand().(CharLiteral).getValue()="62"
}

predicate func_2(Parameter vctxt_5453, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsgStr")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_5453
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="xmlParseEntityDecl: entity %s not terminated\n"
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("const xmlChar *")
}

predicate func_3(Parameter vctxt_5453, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget().getType().hasName("xmlParserInputPtr")
		and target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_5453
}

from Function func, Parameter vctxt_5453, EqualityOperation target_1, ExprStmt target_2, EqualityOperation target_3
where
not func_0(vctxt_5453, target_1, target_2, target_3)
and func_1(vctxt_5453, target_1)
and func_2(vctxt_5453, target_2)
and func_3(vctxt_5453, target_3)
and vctxt_5453.getType().hasName("xmlParserCtxtPtr")
and vctxt_5453.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
