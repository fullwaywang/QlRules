/**
 * @name c-ares-9903253c347f9e0bffd285ae3829aef251cc852d-config_sortlist
 * @id cpp/c-ares/9903253c347f9e0bffd285ae3829aef251cc852d/config-sortlist
 * @description c-ares-9903253c347f9e0bffd285ae3829aef251cc852d-src/lib/ares_init.c-config_sortlist CVE-2022-4904
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstr_1902, Variable vq_1905, BlockStmt target_6, ExprStmt target_7, EqualityOperation target_4) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_0.getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_1902
		and target_0.getLesserOperand().(Literal).getValue()="16"
		and target_0.getParent().(IfStmt).getThen()=target_6
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_4, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="17"
		and target_1.getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vstr_1902, Variable vq_1905, Variable vipbufpfx_1911, Variable vstr2_1921, PointerArithmeticOperation target_8, PointerArithmeticOperation target_9, ExprStmt target_5) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vq_1905
		and target_2.getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="59"
		and target_2.getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vq_1905
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_1902
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="17"
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vipbufpfx_1911
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstr_1902
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_1902
		and target_2.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vipbufpfx_1911
		and target_2.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_2.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_1902
		and target_2.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstr_1902
		and target_2.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstr2_1921
		and target_2.getElse() instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getRightOperand().(VariableAccess).getLocation())
		and target_9.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vstr_1902, Variable vq_1905, EqualityOperation target_4, ExprStmt target_10, ExprStmt target_11, PointerArithmeticOperation target_12) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_1902
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="17"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_11.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_12.getLeftOperand().(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vq_1905, BlockStmt target_6, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vq_1905
		and target_4.getAnOperand().(CharLiteral).getValue()="47"
		and target_4.getParent().(IfStmt).getThen()=target_6
}

predicate func_5(Variable vipbufpfx_1911, EqualityOperation target_4, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vipbufpfx_1911
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_5.getParent().(IfStmt).getCondition()=target_4
}

predicate func_6(Parameter vstr_1902, Variable vq_1905, Variable vipbufpfx_1911, BlockStmt target_6) {
		target_6.getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vq_1905
		and target_6.getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vq_1905
		and target_6.getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="59"
		and target_6.getStmt(1).(WhileStmt).getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vq_1905
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vipbufpfx_1911
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstr_1902
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_6.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_1902
}

predicate func_7(Parameter vstr_1902, Variable vq_1905, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_1902
		and target_7.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_8(Parameter vstr_1902, Variable vq_1905, PointerArithmeticOperation target_8) {
		target_8.getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_8.getRightOperand().(VariableAccess).getTarget()=vstr_1902
}

predicate func_9(Variable vq_1905, PointerArithmeticOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vq_1905
		and target_9.getAnOperand().(Literal).getValue()="1"
}

predicate func_10(Parameter vstr_1902, Variable vq_1905, Variable vipbufpfx_1911, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vipbufpfx_1911
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstr_1902
		and target_10.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_10.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_1902
}

predicate func_11(Variable vq_1905, ExprStmt target_11) {
		target_11.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vq_1905
}

predicate func_12(Parameter vstr_1902, Variable vq_1905, PointerArithmeticOperation target_12) {
		target_12.getLeftOperand().(VariableAccess).getTarget()=vq_1905
		and target_12.getRightOperand().(VariableAccess).getTarget()=vstr_1902
}

from Function func, Parameter vstr_1902, Variable vq_1905, Variable vipbufpfx_1911, Variable vstr2_1921, EqualityOperation target_4, ExprStmt target_5, BlockStmt target_6, ExprStmt target_7, PointerArithmeticOperation target_8, PointerArithmeticOperation target_9, ExprStmt target_10, ExprStmt target_11, PointerArithmeticOperation target_12
where
not func_0(vstr_1902, vq_1905, target_6, target_7, target_4)
and not func_1(target_4, func)
and not func_2(vstr_1902, vq_1905, vipbufpfx_1911, vstr2_1921, target_8, target_9, target_5)
and func_4(vq_1905, target_6, target_4)
and func_5(vipbufpfx_1911, target_4, target_5)
and func_6(vstr_1902, vq_1905, vipbufpfx_1911, target_6)
and func_7(vstr_1902, vq_1905, target_7)
and func_8(vstr_1902, vq_1905, target_8)
and func_9(vq_1905, target_9)
and func_10(vstr_1902, vq_1905, vipbufpfx_1911, target_10)
and func_11(vq_1905, target_11)
and func_12(vstr_1902, vq_1905, target_12)
and vstr_1902.getType().hasName("const char *")
and vq_1905.getType().hasName("const char *")
and vipbufpfx_1911.getType().hasName("char[32]")
and vstr2_1921.getType().hasName("const char *")
and vstr_1902.getParentScope+() = func
and vq_1905.getParentScope+() = func
and vipbufpfx_1911.getParentScope+() = func
and vstr2_1921.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
