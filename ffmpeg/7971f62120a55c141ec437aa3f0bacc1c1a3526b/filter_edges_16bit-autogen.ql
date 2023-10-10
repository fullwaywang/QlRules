/**
 * @name ffmpeg-7971f62120a55c141ec437aa3f0bacc1c1a3526b-filter_edges_16bit
 * @id cpp/ffmpeg/7971f62120a55c141ec437aa3f0bacc1c1a3526b/filter-edges-16bit
 * @description ffmpeg-7971f62120a55c141ec437aa3f0bacc1c1a3526b-libavfilter/vf_yadif.c-filter_edges_16bit CVE-2020-22021
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vw_162, VariableAccess target_0) {
		target_0.getTarget()=vw_162
}

predicate func_1(Parameter vw_162, VariableAccess target_1) {
		target_1.getTarget()=vw_162
}

predicate func_2(Parameter vw_162, VariableAccess target_2) {
		target_2.getTarget()=vw_162
}

predicate func_3(Parameter vw_162, VariableAccess target_3) {
		target_3.getTarget()=vw_162
}

predicate func_4(Variable vx_168, Parameter vw_162, BlockStmt target_19) {
	exists(ConditionalExpr target_4 |
		target_4.getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vw_162
		and target_4.getThen().(VariableAccess).getTarget()=vw_162
		and target_4.getElse().(Literal).getValue()="3"
		and target_4.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vx_168
		and target_4.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_4.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_19)
}

predicate func_6(Parameter vw_162, RelationalOperation target_21, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand() instanceof SubExpr
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vw_162
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(Literal).getValue()="3"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_6)
		and target_21.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

/*predicate func_8(Variable vx_168, Parameter vw_162, RelationalOperation target_21) {
	exists(ConditionalExpr target_8 |
		target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_8.getCondition().(RelationalOperation).getLesserOperand() instanceof SubExpr
		and target_8.getThen().(VariableAccess).getType().hasName("int")
		and target_8.getElse().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vw_162
		and target_8.getElse().(SubExpr).getRightOperand().(Literal).getValue()="3"
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_168
		and target_21.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_8.getElse().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

*/
predicate func_9(Variable vx_168, PostfixIncrExpr target_24) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=vx_168
		and target_9.getRValue().(VariableAccess).getType().hasName("int")
		and target_24.getOperand().(VariableAccess).getLocation().isBefore(target_9.getLValue().(VariableAccess).getLocation()))
}

predicate func_10(Variable vx_168, Variable vedge_172, Parameter vw_162, SubExpr target_10) {
		target_10.getLeftOperand().(VariableAccess).getTarget()=vw_162
		and target_10.getRightOperand().(VariableAccess).getTarget()=vedge_172
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_168
}

/*predicate func_11(Variable vx_168, Parameter vw_162, SubExpr target_11) {
		target_11.getLeftOperand().(VariableAccess).getTarget()=vw_162
		and target_11.getRightOperand().(Literal).getValue()="3"
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_168
}

*/
predicate func_13(Variable vedge_172, VariableAccess target_13) {
		target_13.getTarget()=vedge_172
}

/*predicate func_14(Variable vx_168, Parameter vw_162, VariableAccess target_14) {
		target_14.getTarget()=vx_168
		and target_14.getParent().(AssignExpr).getLValue() = target_14
		and target_14.getParent().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vw_162
		and target_14.getParent().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="3"
}

*/
predicate func_15(Variable vedge_172, Parameter vw_162, Parameter vdst1_161, PointerArithmeticOperation target_15) {
		target_15.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdst1_161
		and target_15.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vw_162
		and target_15.getRightOperand().(VariableAccess).getTarget()=vedge_172
		and target_15.getParent().(AssignExpr).getRValue() = target_15
}

predicate func_16(Variable vedge_172, Parameter vprev1_161, Parameter vw_162, PointerArithmeticOperation target_16) {
		target_16.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vprev1_161
		and target_16.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vw_162
		and target_16.getRightOperand().(VariableAccess).getTarget()=vedge_172
		and target_16.getParent().(AssignExpr).getRValue() = target_16
}

predicate func_17(Variable vedge_172, Parameter vcur1_161, Parameter vw_162, PointerArithmeticOperation target_17) {
		target_17.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcur1_161
		and target_17.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vw_162
		and target_17.getRightOperand().(VariableAccess).getTarget()=vedge_172
		and target_17.getParent().(AssignExpr).getRValue() = target_17
}

predicate func_18(Variable vedge_172, Parameter vnext1_161, Parameter vw_162, PointerArithmeticOperation target_18) {
		target_18.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vnext1_161
		and target_18.getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vw_162
		and target_18.getRightOperand().(VariableAccess).getTarget()=vedge_172
		and target_18.getParent().(AssignExpr).getRValue() = target_18
}

predicate func_19(BlockStmt target_19) {
		target_19.getStmt(8).(IfStmt).getCondition().(Literal).getValue()="0"
		and target_19.getStmt(9).(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_19.getStmt(11).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_21(Variable vx_168, Parameter vw_162, RelationalOperation target_21) {
		 (target_21 instanceof GTExpr or target_21 instanceof LTExpr)
		and target_21.getLesserOperand().(VariableAccess).getTarget()=vx_168
		and target_21.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vw_162
		and target_21.getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="3"
}

predicate func_24(Variable vx_168, PostfixIncrExpr target_24) {
		target_24.getOperand().(VariableAccess).getTarget()=vx_168
}

from Function func, Variable vx_168, Variable vedge_172, Parameter vprev1_161, Parameter vcur1_161, Parameter vnext1_161, Parameter vw_162, Parameter vdst1_161, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, SubExpr target_10, VariableAccess target_13, PointerArithmeticOperation target_15, PointerArithmeticOperation target_16, PointerArithmeticOperation target_17, PointerArithmeticOperation target_18, BlockStmt target_19, RelationalOperation target_21, PostfixIncrExpr target_24
where
func_0(vw_162, target_0)
and func_1(vw_162, target_1)
and func_2(vw_162, target_2)
and func_3(vw_162, target_3)
and not func_4(vx_168, vw_162, target_19)
and not func_6(vw_162, target_21, func)
and not func_9(vx_168, target_24)
and func_10(vx_168, vedge_172, vw_162, target_10)
and func_13(vedge_172, target_13)
and func_15(vedge_172, vw_162, vdst1_161, target_15)
and func_16(vedge_172, vprev1_161, vw_162, target_16)
and func_17(vedge_172, vcur1_161, vw_162, target_17)
and func_18(vedge_172, vnext1_161, vw_162, target_18)
and func_19(target_19)
and func_21(vx_168, vw_162, target_21)
and func_24(vx_168, target_24)
and vx_168.getType().hasName("int")
and vedge_172.getType().hasName("const int")
and vprev1_161.getType().hasName("void *")
and vcur1_161.getType().hasName("void *")
and vnext1_161.getType().hasName("void *")
and vw_162.getType().hasName("int")
and vdst1_161.getType().hasName("void *")
and vx_168.getParentScope+() = func
and vedge_172.getParentScope+() = func
and vprev1_161.getParentScope+() = func
and vcur1_161.getParentScope+() = func
and vnext1_161.getParentScope+() = func
and vw_162.getParentScope+() = func
and vdst1_161.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
