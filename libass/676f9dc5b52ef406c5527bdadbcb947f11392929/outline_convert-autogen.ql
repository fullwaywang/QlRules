/**
 * @name libass-676f9dc5b52ef406c5527bdadbcb947f11392929-outline_convert
 * @id cpp/libass/676f9dc5b52ef406c5527bdadbcb947f11392929/outline-convert
 * @description libass-676f9dc5b52ef406c5527bdadbcb947f11392929-libass/ass_outline.c-outline_convert CVE-2020-26682
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsource_51, Variable vj_65, LogicalOrExpr target_3, BitwiseAndExpr target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("valid_point")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="points"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_51
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vj_65
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(GotoStmt).getName() ="fail"
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsource_51, Variable vlast_70, BitwiseAndExpr target_4, ArrayExpr target_6, ExprStmt target_5) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("valid_point")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="points"
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_51
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlast_70
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(GotoStmt).getName() ="fail"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsource_51, Variable vj_65, ArrayExpr target_7, BitwiseAndExpr target_8, PostfixIncrExpr target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("valid_point")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="points"
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_51
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vj_65
		and target_2.getThen().(GotoStmt).toString() = "goto ..."
		and target_2.getThen().(GotoStmt).getName() ="fail"
		and target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vsource_51, Variable vj_65, Variable vlast_70, LogicalOrExpr target_3) {
		target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vj_65
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlast_70
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlast_70
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="n_points"
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_51
}

predicate func_4(Parameter vsource_51, Variable vj_65, BitwiseAndExpr target_4) {
		target_4.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tags"
		and target_4.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_51
		and target_4.getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_65
		and target_4.getRightOperand().(Literal).getValue()="3"
}

predicate func_5(Variable vj_65, Variable vlast_70, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_65
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlast_70
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_6(Parameter vsource_51, Variable vlast_70, ArrayExpr target_6) {
		target_6.getArrayBase().(PointerFieldAccess).getTarget().getName()="points"
		and target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_51
		and target_6.getArrayOffset().(VariableAccess).getTarget()=vlast_70
}

predicate func_7(Parameter vsource_51, Variable vj_65, ArrayExpr target_7) {
		target_7.getArrayBase().(PointerFieldAccess).getTarget().getName()="points"
		and target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_51
		and target_7.getArrayOffset().(VariableAccess).getTarget()=vj_65
}

predicate func_8(Parameter vsource_51, Variable vj_65, BitwiseAndExpr target_8) {
		target_8.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tags"
		and target_8.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsource_51
		and target_8.getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_65
		and target_8.getRightOperand().(Literal).getValue()="3"
}

predicate func_9(Variable vj_65, PostfixIncrExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vj_65
}

from Function func, Parameter vsource_51, Variable vj_65, Variable vlast_70, LogicalOrExpr target_3, BitwiseAndExpr target_4, ExprStmt target_5, ArrayExpr target_6, ArrayExpr target_7, BitwiseAndExpr target_8, PostfixIncrExpr target_9
where
not func_0(vsource_51, vj_65, target_3, target_4, target_5)
and not func_1(vsource_51, vlast_70, target_4, target_6, target_5)
and not func_2(vsource_51, vj_65, target_7, target_8, target_9)
and func_3(vsource_51, vj_65, vlast_70, target_3)
and func_4(vsource_51, vj_65, target_4)
and func_5(vj_65, vlast_70, target_5)
and func_6(vsource_51, vlast_70, target_6)
and func_7(vsource_51, vj_65, target_7)
and func_8(vsource_51, vj_65, target_8)
and func_9(vj_65, target_9)
and vsource_51.getType().hasName("const FT_Outline *")
and vj_65.getType().hasName("size_t")
and vlast_70.getType().hasName("int")
and vsource_51.getParentScope+() = func
and vj_65.getParentScope+() = func
and vlast_70.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
