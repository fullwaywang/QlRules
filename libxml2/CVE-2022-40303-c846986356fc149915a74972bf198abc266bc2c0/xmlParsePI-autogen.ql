/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParsePI
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParsePI
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParsePI CVE-2022-40303
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

predicate func_1(Variable vlen_5160) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vlen_5160)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition() instanceof BitwiseAndExpr
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="1000000000"
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_2)
}

predicate func_3(Parameter vctxt_5158) {
	exists(BitwiseAndExpr target_3 |
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_5158)
}

predicate func_4(Variable vbuf_5159, Variable vxmlFree) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_4.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_5159
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof LogicalAndExpr)
}

predicate func_5(Variable vstate_5164, Parameter vctxt_5158) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="instate"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_5158
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstate_5164
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof LogicalAndExpr)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="10000000"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vlen_5160, Variable vtarget_5163, Variable vstate_5164, Parameter vctxt_5158, Variable vbuf_5159, Variable vxmlFree) {
	exists(LogicalAndExpr target_7 |
		target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_5160
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsgStr")
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_5158
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtarget_5163
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_5159
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="instate"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_5158
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstate_5164
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(3).(ReturnStmt).toString() = "return ...")
}

predicate func_8(Variable vlen_5160, Variable vtarget_5163, Parameter vctxt_5158) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_5160
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="10000000"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_5158
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsgStr")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_5158
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtarget_5163
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtarget_5163
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

from Function func, Variable vlen_5160, Variable vtarget_5163, Variable vstate_5164, Parameter vctxt_5158, Variable vbuf_5159, Variable vxmlFree
where
func_0(func)
and func_1(vlen_5160)
and not func_2(func)
and func_3(vctxt_5158)
and func_4(vbuf_5159, vxmlFree)
and func_5(vstate_5164, vctxt_5158)
and func_6(func)
and func_7(vlen_5160, vtarget_5163, vstate_5164, vctxt_5158, vbuf_5159, vxmlFree)
and func_8(vlen_5160, vtarget_5163, vctxt_5158)
and vlen_5160.getType().hasName("size_t")
and vtarget_5163.getType().hasName("const xmlChar *")
and vstate_5164.getType().hasName("xmlParserInputState")
and vctxt_5158.getType().hasName("xmlParserCtxtPtr")
and vbuf_5159.getType().hasName("xmlChar *")
and vxmlFree.getType().hasName("xmlFreeFunc")
and vlen_5160.getParentScope+() = func
and vtarget_5163.getParentScope+() = func
and vstate_5164.getParentScope+() = func
and vctxt_5158.getParentScope+() = func
and vbuf_5159.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
