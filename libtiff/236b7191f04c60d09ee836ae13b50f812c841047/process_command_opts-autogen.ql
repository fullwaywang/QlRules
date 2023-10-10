/**
 * @name libtiff-236b7191f04c60d09ee836ae13b50f812c841047-process_command_opts
 * @id cpp/libtiff/236b7191f04c60d09ee836ae13b50f812c841047/process-command-opts
 * @description libtiff-236b7191f04c60d09ee836ae13b50f812c841047-tools/tiffcrop.c-process_command_opts CVE-2022-3597
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="The crop options(-X|-Y), -Z, -z and -S are mutually exclusive.->Exit"
		and not target_0.getValue()="The crop options(-X|-Y), -Z, -z and -S are mutually exclusive.->exit"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vpage_1629, Variable vXY_2135, Variable vZ_2135, Variable vR_2135, ExprStmt target_2, RelationalOperation target_3, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vXY_2135
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vZ_2135
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vR_2135
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_1629
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="tiffcrop input error"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Any of the crop options -X, -Y, -Z and -z together with other PAGE_MODE_x options such as - H, -V, -P, -J or -K is not supported and may cause buffer overflows..->exit"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_1)
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpage_1629, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char")
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpage_1629
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_3(Variable vXY_2135, Variable vZ_2135, Variable vR_2135, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vXY_2135
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vZ_2135
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vR_2135
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("char")
		and target_3.getLesserOperand().(Literal).getValue()="1"
}

from Function func, Parameter vpage_1629, Variable vXY_2135, Variable vZ_2135, Variable vR_2135, StringLiteral target_0, ExprStmt target_2, RelationalOperation target_3
where
func_0(func, target_0)
and not func_1(vpage_1629, vXY_2135, vZ_2135, vR_2135, target_2, target_3, func)
and func_2(vpage_1629, target_2)
and func_3(vXY_2135, vZ_2135, vR_2135, target_3)
and vpage_1629.getType().hasName("pagedef *")
and vXY_2135.getType().hasName("char")
and vZ_2135.getType().hasName("char")
and vR_2135.getType().hasName("char")
and vpage_1629.getFunction() = func
and vXY_2135.(LocalVariable).getFunction() = func
and vZ_2135.(LocalVariable).getFunction() = func
and vR_2135.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
