/**
 * @name vim-bd228fd097b41a798f90944b5d1245eddd484142-find_help_tags
 * @id cpp/vim/bd228fd097b41a798f90944b5d1245eddd484142/find-help-tags
 * @description vim-bd228fd097b41a798f90944b5d1245eddd484142-src/help.c-find_help_tags CVE-2021-4019
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="3"
		and not target_0.getValue()="1024"
		and target_0.getParent().(PointerAddExpr).getParent().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vd_325, EqualityOperation target_6, PointerArithmeticOperation target_7) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("vim_snprintf")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vd_325
		and target_1.getArgument(1).(AddExpr).getValue()="1025"
		and target_1.getArgument(2).(StringLiteral).getValue()="/\\\\%s"
		and target_1.getArgument(3) instanceof PointerArithmeticOperation
		and target_6.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation())
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter varg_320, PointerArithmeticOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=varg_320
		and target_2.getAnOperand().(Literal).getValue()="1"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Variable vd_325, VariableAccess target_3) {
		target_3.getTarget()=vd_325
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Variable vd_325, FunctionCall target_4) {
		target_4.getTarget().hasName("strcpy")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vd_325
		and target_4.getArgument(1).(StringLiteral).getValue()="/\\\\"
}

predicate func_5(Variable vd_325, LogicalAndExpr target_8, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("strcpy")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vd_325
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof PointerArithmeticOperation
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_6(Variable vd_325, EqualityOperation target_6) {
		target_6.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vd_325
		and target_6.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Variable vd_325, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vd_325
		and target_7.getAnOperand() instanceof Literal
}

predicate func_8(Parameter varg_320, LogicalAndExpr target_8) {
		target_8.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=varg_320
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=varg_320
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=varg_320
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("vim_strchr")
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%_z@"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=varg_320
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=varg_320
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vd_325, Parameter varg_320, Literal target_0, PointerArithmeticOperation target_2, VariableAccess target_3, FunctionCall target_4, ExprStmt target_5, EqualityOperation target_6, PointerArithmeticOperation target_7, LogicalAndExpr target_8
where
func_0(func, target_0)
and not func_1(vd_325, target_6, target_7)
and func_2(varg_320, target_2)
and func_3(vd_325, target_3)
and func_4(vd_325, target_4)
and func_5(vd_325, target_8, target_5)
and func_6(vd_325, target_6)
and func_7(vd_325, target_7)
and func_8(varg_320, target_8)
and vd_325.getType().hasName("char_u *")
and varg_320.getType().hasName("char_u *")
and vd_325.getParentScope+() = func
and varg_320.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
