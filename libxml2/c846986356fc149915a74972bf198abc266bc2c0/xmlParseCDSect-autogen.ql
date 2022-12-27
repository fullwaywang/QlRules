/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseCDSect
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseCDSect
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseCDSect CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsize_9761) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vsize_9761)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="0"
		and not target_1.getValue()="1000000000"
		and target_1.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vctxt_9758) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("xmlFatalErrMsgStr")
		and not target_2.getTarget().hasName("xmlFatalErrMsg")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctxt_9758
		and target_2.getArgument(2).(StringLiteral).getValue()="CData section too big found"
		and target_2.getArgument(3).(Literal).getValue()="0")
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition() instanceof BitwiseAndExpr
		and target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="1000000000"
		and target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(7)=target_3)
}

predicate func_5(Function func) {
	exists(StringLiteral target_5 |
		target_5.getValue()="CData section too big found\n"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vbuf_9759, Variable vxmlFree, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_6.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_9759
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_6))
}

predicate func_7(Parameter vctxt_9758) {
	exists(BitwiseAndExpr target_7 |
		target_7.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_7.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9758)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="10000000"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Variable vsize_9761) {
	exists(LogicalAndExpr target_11 |
		target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_9761
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_11.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_11.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).toString() = "return ...")
}

predicate func_12(Parameter vctxt_9758, Variable vbuf_9759, Variable vlen_9760) {
	exists(VariableCall target_12 |
		target_12.getExpr().(PointerFieldAccess).getTarget().getName()="characters"
		and target_12.getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_12.getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9758
		and target_12.getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_12.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9758
		and target_12.getArgument(1).(VariableAccess).getTarget()=vbuf_9759
		and target_12.getArgument(2).(VariableAccess).getTarget()=vlen_9760)
}

predicate func_13(Variable vbuf_9759, Variable vxmlFree) {
	exists(VariableCall target_13 |
		target_13.getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_13.getArgument(0).(VariableAccess).getTarget()=vbuf_9759)
}

from Function func, Parameter vctxt_9758, Variable vbuf_9759, Variable vlen_9760, Variable vsize_9761, Variable vxmlFree
where
func_0(vsize_9761)
and func_1(func)
and func_2(vctxt_9758)
and not func_3(func)
and not func_5(func)
and not func_6(vbuf_9759, vxmlFree, func)
and func_7(vctxt_9758)
and func_10(func)
and func_11(vsize_9761)
and vctxt_9758.getType().hasName("xmlParserCtxtPtr")
and vbuf_9759.getType().hasName("xmlChar *")
and func_12(vctxt_9758, vbuf_9759, vlen_9760)
and vlen_9760.getType().hasName("int")
and vsize_9761.getType().hasName("int")
and vxmlFree.getType().hasName("xmlFreeFunc")
and func_13(vbuf_9759, vxmlFree)
and vctxt_9758.getParentScope+() = func
and vbuf_9759.getParentScope+() = func
and vlen_9760.getParentScope+() = func
and vsize_9761.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
