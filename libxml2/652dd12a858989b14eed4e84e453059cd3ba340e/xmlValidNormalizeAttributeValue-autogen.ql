/**
 * @name libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlValidNormalizeAttributeValue
 * @id cpp/libxml2/652dd12a858989b14eed4e84e453059cd3ba340e/xmlValidNormalizeAttributeValue
 * @description libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-valid.c-xmlValidNormalizeAttributeValue CVE-2022-23308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_4117, EqualityOperation target_13, ReturnStmt target_14) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xmlValidNormalizeString")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vret_4117
		and target_13.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getExpr().(VariableAccess).getLocation()))
}

predicate func_1(Variable vret_4117, Variable vdst_4117, VariableAccess target_1) {
		target_1.getTarget()=vret_4117
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdst_4117
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Parameter vvalue_4116, Variable vsrc_4118, AssignExpr target_4) {
		target_4.getLValue().(VariableAccess).getTarget()=vsrc_4118
		and target_4.getRValue().(VariableAccess).getTarget()=vvalue_4116
}

predicate func_5(Variable vret_4117, Variable vdst_4117, Function func, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdst_4117
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vret_4117
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vsrc_4118, Function func, WhileStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_6.getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="32"
		and target_6.getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Variable vsrc_4118, Function func, WhileStmt target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_7.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="32"
		and target_7.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="32"
		and target_7.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

/*predicate func_8(Variable vdst_4117, Variable vsrc_4118, IfStmt target_8) {
		target_8.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_8.getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="32"
		and target_8.getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_8.getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="32"
		and target_8.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="32"
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdst_4117
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
}

*/
/*predicate func_9(Variable vsrc_4118, EqualityOperation target_17, WhileStmt target_9) {
		target_9.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_9.getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="32"
		and target_9.getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

*/
/*predicate func_10(Variable vdst_4117, Variable vsrc_4118, EqualityOperation target_17, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_10.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdst_4117
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="32"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

*/
/*predicate func_11(Variable vdst_4117, Variable vsrc_4118, EqualityOperation target_17, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdst_4117
		and target_11.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_4118
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

*/
predicate func_12(Variable vdst_4117, Function func, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdst_4117
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Variable vret_4117, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vret_4117
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vret_4117, ReturnStmt target_14) {
		target_14.getExpr().(VariableAccess).getTarget()=vret_4117
}

predicate func_17(EqualityOperation target_17) {
		target_17.getAnOperand() instanceof PointerDereferenceExpr
		and target_17.getAnOperand() instanceof HexLiteral
}

from Function func, Parameter vvalue_4116, Variable vret_4117, Variable vdst_4117, Variable vsrc_4118, VariableAccess target_1, DeclStmt target_3, AssignExpr target_4, ExprStmt target_5, WhileStmt target_6, WhileStmt target_7, ExprStmt target_12, EqualityOperation target_13, ReturnStmt target_14, EqualityOperation target_17
where
not func_0(vret_4117, target_13, target_14)
and func_1(vret_4117, vdst_4117, target_1)
and func_3(func, target_3)
and func_4(vvalue_4116, vsrc_4118, target_4)
and func_5(vret_4117, vdst_4117, func, target_5)
and func_6(vsrc_4118, func, target_6)
and func_7(vsrc_4118, func, target_7)
and func_12(vdst_4117, func, target_12)
and func_13(vret_4117, target_13)
and func_14(vret_4117, target_14)
and func_17(target_17)
and vvalue_4116.getType().hasName("const xmlChar *")
and vret_4117.getType().hasName("xmlChar *")
and vdst_4117.getType().hasName("xmlChar *")
and vsrc_4118.getType().hasName("const xmlChar *")
and vvalue_4116.getFunction() = func
and vret_4117.(LocalVariable).getFunction() = func
and vdst_4117.(LocalVariable).getFunction() = func
and vsrc_4118.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
