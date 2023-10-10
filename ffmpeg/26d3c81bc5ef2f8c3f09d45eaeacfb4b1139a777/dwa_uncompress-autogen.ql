/**
 * @name ffmpeg-26d3c81bc5ef2f8c3f09d45eaeacfb4b1139a777-dwa_uncompress
 * @id cpp/ffmpeg/26d3c81bc5ef2f8c3f09d45eaeacfb4b1139a777/dwa-uncompress
 * @description ffmpeg-26d3c81bc5ef2f8c3f09d45eaeacfb4b1139a777-libavcodec/exr.c-dwa_uncompress CVE-2021-33815
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="3"
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vdc_count_993, Variable vdc_w_994, Variable vdc_h_995, ReturnStmt target_5, MulExpr target_6, LogicalOrExpr target_7, AddExpr target_8) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vdc_count_993
		and target_1.getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vdc_w_994
		and target_1.getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vdc_h_995
		and target_1.getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_1.getParent().(IfStmt).getThen()=target_5
		and target_6.getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vdc_count_993, ReturnStmt target_5, VariableAccess target_2) {
		target_2.getTarget()=vdc_count_993
		and target_2.getParent().(GTExpr).getLesserOperand() instanceof DivExpr
		and target_2.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_3(Parameter vtd_989, Variable vdc_size_992, Variable vdc_count_993, Variable vgb_996, Variable vdest_len_1063, Parameter vs_988, Function func, IfStmt target_3) {
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdc_size_992
		and target_3.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdc_count_993
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="63"
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(Literal).getValue()="64"
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_fast_padded_malloc")
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dc_data"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_989
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dc_size"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_989
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_3.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dc_data"
		and target_3.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_989
		and target_3.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_3.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("uncompress")
		and target_3.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="buffer"
		and target_3.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdc_size_992
		and target_3.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdest_len_1063
		and target_3.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vdc_count_993
		and target_3.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_3.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="predictor"
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dsp"
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_988
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dc_data"
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_989
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vdest_len_1063
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="reorder_pixels"
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dsp"
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_988
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dc_data"
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_989
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dc_data"
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_989
		and target_3.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vdest_len_1063
		and target_3.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("bytestream2_skip")
		and target_3.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_996
		and target_3.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdc_size_992
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

/*predicate func_4(Parameter vtd_989, Variable vdc_count_993, ReturnStmt target_5, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vdc_count_993
		and target_4.getLesserOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="6"
		and target_4.getLesserOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="xsize"
		and target_4.getLesserOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_989
		and target_4.getLesserOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ysize"
		and target_4.getLesserOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_989
		and target_4.getLesserOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="63"
		and target_4.getLesserOperand().(DivExpr).getRightOperand().(Literal).getValue()="64"
		and target_4.getParent().(IfStmt).getThen()=target_5
}

*/
predicate func_5(ReturnStmt target_5) {
		target_5.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

predicate func_6(Variable vdc_count_993, MulExpr target_6) {
		target_6.getLeftOperand().(VariableAccess).getTarget()=vdc_count_993
		and target_6.getRightOperand().(Literal).getValue()="2"
}

predicate func_7(Parameter vtd_989, Variable vdc_size_992, Variable vdc_count_993, Variable vdest_len_1063, LogicalOrExpr target_7) {
		target_7.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("uncompress")
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dc_data"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_989
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="18446744073709551552"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdest_len_1063
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="buffer"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdc_size_992
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdest_len_1063
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vdc_count_993
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_8(Variable vdc_w_994, Variable vdc_h_995, AddExpr target_8) {
		target_8.getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_8.getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_8.getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vdc_w_994
		and target_8.getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vdc_w_994
		and target_8.getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vdc_h_995
}

from Function func, Parameter vtd_989, Variable vdc_size_992, Variable vdc_count_993, Variable vdc_w_994, Variable vdc_h_995, Variable vgb_996, Variable vdest_len_1063, Parameter vs_988, Literal target_0, VariableAccess target_2, IfStmt target_3, ReturnStmt target_5, MulExpr target_6, LogicalOrExpr target_7, AddExpr target_8
where
func_0(func, target_0)
and not func_1(vdc_count_993, vdc_w_994, vdc_h_995, target_5, target_6, target_7, target_8)
and func_2(vdc_count_993, target_5, target_2)
and func_3(vtd_989, vdc_size_992, vdc_count_993, vgb_996, vdest_len_1063, vs_988, func, target_3)
and func_5(target_5)
and func_6(vdc_count_993, target_6)
and func_7(vtd_989, vdc_size_992, vdc_count_993, vdest_len_1063, target_7)
and func_8(vdc_w_994, vdc_h_995, target_8)
and vtd_989.getType().hasName("EXRThreadData *")
and vdc_size_992.getType().hasName("int64_t")
and vdc_count_993.getType().hasName("int64_t")
and vdc_w_994.getType().hasName("const int")
and vdc_h_995.getType().hasName("const int")
and vgb_996.getType().hasName("GetByteContext")
and vdest_len_1063.getType().hasName("unsigned long")
and vs_988.getType().hasName("EXRContext *")
and vtd_989.getParentScope+() = func
and vdc_size_992.getParentScope+() = func
and vdc_count_993.getParentScope+() = func
and vdc_w_994.getParentScope+() = func
and vdc_h_995.getParentScope+() = func
and vgb_996.getParentScope+() = func
and vdest_len_1063.getParentScope+() = func
and vs_988.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
