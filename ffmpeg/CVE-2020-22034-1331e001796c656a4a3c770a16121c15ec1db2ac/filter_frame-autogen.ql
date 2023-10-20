/**
 * @name ffmpeg-1331e001796c656a4a3c770a16121c15ec1db2ac-filter_frame
 * @id cpp/ffmpeg/1331e001796c656a4a3c770a16121c15ec1db2ac/filter-frame
 * @description ffmpeg-1331e001796c656a4a3c770a16121c15ec1db2ac-libavfilter/vf_floodfill.c-filter_frame CVE-2020-22034
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_282, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="d0"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_282
}

predicate func_1(Variable vs_282, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="d1"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_282
}

predicate func_2(Variable vs_282) {
	exists(ArrayExpr target_2 |
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="d"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_2.getArrayOffset().(Literal).getValue()="0")
}

predicate func_3(Variable vs_282) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="d"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_3.getArrayOffset().(Literal).getValue()="1")
}

predicate func_4(Variable vs_282) {
	exists(ArrayExpr target_4 |
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="d"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_4.getArrayOffset().(Literal).getValue()="2")
}

predicate func_5(Variable vs_282) {
	exists(ArrayExpr target_5 |
		target_5.getArrayBase().(PointerFieldAccess).getTarget().getName()="d"
		and target_5.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_5.getArrayOffset().(Literal).getValue()="3")
}

predicate func_6(Variable vs_282) {
	exists(ArrayExpr target_6 |
		target_6.getArrayBase().(PointerFieldAccess).getTarget().getName()="s"
		and target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_6.getArrayOffset().(Literal).getValue()="0")
}

predicate func_7(Variable vs_282, FunctionCall target_25) {
	exists(ArrayExpr target_7 |
		target_7.getArrayBase().(PointerFieldAccess).getTarget().getName()="s"
		and target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_7.getArrayOffset().(Literal).getValue()="1"
		and target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Variable vs_282) {
	exists(ArrayExpr target_8 |
		target_8.getArrayBase().(PointerFieldAccess).getTarget().getName()="s"
		and target_8.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_8.getArrayOffset().(Literal).getValue()="2")
}

predicate func_9(Variable vs_282) {
	exists(ArrayExpr target_9 |
		target_9.getArrayBase().(PointerFieldAccess).getTarget().getName()="s"
		and target_9.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_9.getArrayOffset().(Literal).getValue()="3")
}

predicate func_11(Variable vs_282, Function func) {
	exists(IfStmt target_11 |
		target_11.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nb_planes"
		and target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_11.getThen().(GotoStmt).toString() = "goto ..."
		and target_11.getThen().(GotoStmt).getName() ="end"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_11))
}

predicate func_12(Function func) {
	exists(LabelStmt target_12 |
		target_12.toString() = "label ...:"
		and target_12.getName() ="end"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_12))
}

predicate func_13(Variable vs_282, VariableAccess target_13) {
		target_13.getTarget()=vs_282
}

predicate func_14(Variable vs_282, VariableAccess target_14) {
		target_14.getTarget()=vs_282
}

predicate func_15(Variable vs_282, VariableAccess target_15) {
		target_15.getTarget()=vs_282
}

predicate func_16(Variable vs_282, VariableAccess target_16) {
		target_16.getTarget()=vs_282
}

predicate func_17(Variable vs_282, VariableAccess target_17) {
		target_17.getTarget()=vs_282
}

predicate func_18(Variable vs_282, VariableAccess target_18) {
		target_18.getTarget()=vs_282
}

predicate func_19(Variable vs_282, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="d2"
		and target_19.getQualifier().(VariableAccess).getTarget()=vs_282
}

predicate func_20(Variable vs_282, PointerFieldAccess target_20) {
		target_20.getTarget().getName()="d3"
		and target_20.getQualifier().(VariableAccess).getTarget()=vs_282
}

predicate func_21(Variable vs_282, PointerFieldAccess target_21) {
		target_21.getTarget().getName()="s0"
		and target_21.getQualifier().(VariableAccess).getTarget()=vs_282
}

predicate func_22(Variable vs_282, PointerFieldAccess target_22) {
		target_22.getTarget().getName()="s1"
		and target_22.getQualifier().(VariableAccess).getTarget()=vs_282
}

predicate func_23(Variable vs_282, PointerFieldAccess target_23) {
		target_23.getTarget().getName()="s2"
		and target_23.getQualifier().(VariableAccess).getTarget()=vs_282
}

predicate func_24(Variable vs_282, PointerFieldAccess target_24) {
		target_24.getTarget().getName()="s3"
		and target_24.getQualifier().(VariableAccess).getTarget()=vs_282
}

predicate func_25(Variable vs_282, FunctionCall target_25) {
		target_25.getTarget().hasName("is_inside")
		and target_25.getArgument(0).(PointerFieldAccess).getTarget().getName()="x"
		and target_25.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
		and target_25.getArgument(1).(PointerFieldAccess).getTarget().getName()="y"
		and target_25.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_282
}

from Function func, Variable vs_282, PointerFieldAccess target_0, PointerFieldAccess target_1, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, VariableAccess target_16, VariableAccess target_17, VariableAccess target_18, PointerFieldAccess target_19, PointerFieldAccess target_20, PointerFieldAccess target_21, PointerFieldAccess target_22, PointerFieldAccess target_23, PointerFieldAccess target_24, FunctionCall target_25
where
func_0(vs_282, target_0)
and func_1(vs_282, target_1)
and not func_2(vs_282)
and not func_3(vs_282)
and not func_4(vs_282)
and not func_5(vs_282)
and not func_6(vs_282)
and not func_7(vs_282, target_25)
and not func_8(vs_282)
and not func_9(vs_282)
and not func_11(vs_282, func)
and not func_12(func)
and func_13(vs_282, target_13)
and func_14(vs_282, target_14)
and func_15(vs_282, target_15)
and func_16(vs_282, target_16)
and func_17(vs_282, target_17)
and func_18(vs_282, target_18)
and func_19(vs_282, target_19)
and func_20(vs_282, target_20)
and func_21(vs_282, target_21)
and func_22(vs_282, target_22)
and func_23(vs_282, target_23)
and func_24(vs_282, target_24)
and func_25(vs_282, target_25)
and vs_282.getType().hasName("FloodfillContext *")
and vs_282.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
