/**
 * @name libpng-d572394c2a018ef22e9685ac189f5f05c08ea6f5-png_set_rgb_to_gray
 * @id cpp/libpng/d572394c2a018ef22e9685ac189f5f05c08ea6f5/png-set-rgb-to-gray
 * @description libpng-d572394c2a018ef22e9685ac189f5f05c08ea6f5-pngrtran.c-png_set_rgb_to_gray CVE-2011-2690
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_676, Parameter vred_676, Parameter vgreen_677, Variable vred_fixed_679, Variable vgreen_fixed_680, EqualityOperation target_6, AddExpr target_1, AddExpr target_2, ExprStmt target_7, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vred_676
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="21474.83646999999837"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vred_676
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-21474.83648000000176"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vgreen_677
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="21474.83646999999837"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vgreen_677
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-21474.83648000000176"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_warning")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_676
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ignoring out of range rgb_to_gray coefficients"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vred_fixed_679
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vgreen_fixed_680
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vred_fixed_679
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof AddExpr
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vgreen_fixed_680
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof AddExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vred_676, AddExpr target_1) {
		target_1.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vred_676
		and target_1.getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="100000.0"
		and target_1.getAnOperand().(Literal).getValue()="0.5"
}

predicate func_2(Parameter vgreen_677, AddExpr target_2) {
		target_2.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vgreen_677
		and target_2.getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="100000.0"
		and target_2.getAnOperand().(Literal).getValue()="0.5"
}

predicate func_3(Function func, Initializer target_3) {
		target_3.getExpr() instanceof AddExpr
		and target_3.getExpr().getEnclosingFunction() = func
}

predicate func_4(Function func, DeclStmt target_4) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Function func, Initializer target_5) {
		target_5.getExpr() instanceof AddExpr
		and target_5.getExpr().getEnclosingFunction() = func
}

predicate func_6(Parameter vpng_ptr_676, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vpng_ptr_676
		and target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Parameter vpng_ptr_676, Variable vred_fixed_679, Variable vgreen_fixed_680, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("png_set_rgb_to_gray_fixed")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_676
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vred_fixed_679
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vgreen_fixed_680
}

from Function func, Parameter vpng_ptr_676, Parameter vred_676, Parameter vgreen_677, Variable vred_fixed_679, Variable vgreen_fixed_680, AddExpr target_1, AddExpr target_2, Initializer target_3, DeclStmt target_4, Initializer target_5, EqualityOperation target_6, ExprStmt target_7
where
not func_0(vpng_ptr_676, vred_676, vgreen_677, vred_fixed_679, vgreen_fixed_680, target_6, target_1, target_2, target_7, func)
and func_1(vred_676, target_1)
and func_2(vgreen_677, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(vpng_ptr_676, target_6)
and func_7(vpng_ptr_676, vred_fixed_679, vgreen_fixed_680, target_7)
and vpng_ptr_676.getType().hasName("png_structp")
and vred_676.getType().hasName("double")
and vgreen_677.getType().hasName("double")
and vred_fixed_679.getType().hasName("int")
and vgreen_fixed_680.getType().hasName("int")
and vpng_ptr_676.getParentScope+() = func
and vred_676.getParentScope+() = func
and vgreen_677.getParentScope+() = func
and vred_fixed_679.getParentScope+() = func
and vgreen_fixed_680.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
