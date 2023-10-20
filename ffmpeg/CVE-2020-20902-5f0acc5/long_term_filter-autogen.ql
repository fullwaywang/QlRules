/**
 * @name ffmpeg-5f0acc5064ed501cb40d4aaccae2b3ce5c4552fd-long_term_filter
 * @id cpp/ffmpeg/5f0acc5064ed501cb40d4aaccae2b3ce5c4552fd/long-term-filter
 * @description ffmpeg-5f0acc5064ed501cb40d4aaccae2b3ce5c4552fd-libavcodec/g729postfilter.c-long_term_filter CVE-2020-20902
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand() instanceof SubExpr
		and target_0.getRightOperand().(Literal).getValue()="2"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vshift_120, RelationalOperation target_6, ExprStmt target_7) {
	exists(AssignMulExpr target_1 |
		target_1.getLValue() instanceof ArrayExpr
		and target_1.getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vshift_120
		and target_6.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getLocation())
		and target_1.getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignRShiftExpr).getRValue().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsh_gain_num_127, Variable vsh_gain_long_num_131, SubExpr target_2) {
		target_2.getLeftOperand().(VariableAccess).getTarget()=vsh_gain_long_num_131
		and target_2.getRightOperand().(VariableAccess).getTarget()=vsh_gain_num_127
}

predicate func_3(Variable vi_114, Variable vselected_signal_138, ArrayExpr target_3) {
		target_3.getArrayBase().(VariableAccess).getTarget()=vselected_signal_138
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vi_114
}

predicate func_4(Variable vshift_120, VariableAccess target_4) {
		target_4.getTarget()=vshift_120
}

predicate func_5(Variable vshift_120, AssignLShiftExpr target_5) {
		target_5.getLValue() instanceof ArrayExpr
		and target_5.getRValue().(VariableAccess).getTarget()=vshift_120
}

predicate func_6(Variable vshift_120, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vshift_120
		and target_6.getLesserOperand().(Literal).getValue()="0"
}

predicate func_7(Variable vi_114, Variable vshift_120, Variable vselected_signal_138, ExprStmt target_7) {
		target_7.getExpr().(AssignRShiftExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vselected_signal_138
		and target_7.getExpr().(AssignRShiftExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_114
		and target_7.getExpr().(AssignRShiftExpr).getRValue().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vshift_120
}

from Function func, Variable vi_114, Variable vshift_120, Variable vsh_gain_num_127, Variable vsh_gain_long_num_131, Variable vselected_signal_138, SubExpr target_2, ArrayExpr target_3, VariableAccess target_4, AssignLShiftExpr target_5, RelationalOperation target_6, ExprStmt target_7
where
not func_0(func)
and not func_1(vshift_120, target_6, target_7)
and func_2(vsh_gain_num_127, vsh_gain_long_num_131, target_2)
and func_3(vi_114, vselected_signal_138, target_3)
and func_4(vshift_120, target_4)
and func_5(vshift_120, target_5)
and func_6(vshift_120, target_6)
and func_7(vi_114, vshift_120, vselected_signal_138, target_7)
and vi_114.getType().hasName("int")
and vshift_120.getType().hasName("int16_t")
and vsh_gain_num_127.getType().hasName("int16_t")
and vsh_gain_long_num_131.getType().hasName("int16_t")
and vselected_signal_138.getType().hasName("int16_t *")
and vi_114.getParentScope+() = func
and vshift_120.getParentScope+() = func
and vsh_gain_num_127.getParentScope+() = func
and vsh_gain_long_num_131.getParentScope+() = func
and vselected_signal_138.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
