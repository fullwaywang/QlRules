/**
 * @name vim-54e5fed6d27b747ff152cdb6edfb72ff60e70939-spell_dump_compl
 * @id cpp/vim/54e5fed6d27b747ff152cdb6edfb72ff60e70939/spell-dump-compl
 * @description vim-54e5fed6d27b747ff152cdb6edfb72ff60e70939-src/spell.c-spell_dump_compl CVE-2022-2304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdepth_3883, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdepth_3883
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="253"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(PrefixIncrExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc_3878, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vc_3878
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vc_3878, Variable vdepth_3883, BlockStmt target_2) {
		target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="lp_region"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vdepth_3883
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3878
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_3878
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dump_word")
}

predicate func_3(Variable vdepth_3883, ExprStmt target_3) {
		target_3.getExpr().(PrefixIncrExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vdepth_3883
}

predicate func_4(Variable vdepth_3883, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vdepth_3883
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vc_3878, Variable vdepth_3883, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vdepth_3883, target_2, target_3, target_4)
and func_1(vc_3878, target_2, target_1)
and func_2(vc_3878, vdepth_3883, target_2)
and func_3(vdepth_3883, target_3)
and func_4(vdepth_3883, target_4)
and vc_3878.getType().hasName("int")
and vdepth_3883.getType().hasName("int")
and vc_3878.getParentScope+() = func
and vdepth_3883.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
