/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseCommentComplex
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseCommentComplex
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseCommentComplex CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and not target_0.getValue()="1000000000"
		and target_0.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition() instanceof BitwiseAndExpr
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="1000000000"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_1)
}

predicate func_3(Parameter vctxt_4739) {
	exists(BitwiseAndExpr target_3 |
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4739)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="10000000"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vbuf_4739, Parameter vlen_4740, Parameter vctxt_4739, Variable vxmlFree) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_4740
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_5.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_5.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsgStr")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_4739
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Comment too big found"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_4739
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).toString() = "return ...")
}

from Function func, Parameter vbuf_4739, Parameter vlen_4740, Parameter vctxt_4739, Variable vxmlFree
where
func_0(func)
and not func_1(func)
and func_3(vctxt_4739)
and func_4(func)
and func_5(vbuf_4739, vlen_4740, vctxt_4739, vxmlFree)
and vbuf_4739.getType().hasName("xmlChar *")
and vlen_4740.getType().hasName("size_t")
and vctxt_4739.getType().hasName("xmlParserCtxtPtr")
and vxmlFree.getType().hasName("xmlFreeFunc")
and vbuf_4739.getParentScope+() = func
and vlen_4740.getParentScope+() = func
and vctxt_4739.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
