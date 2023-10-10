/**
 * @name ffmpeg-8b94df0f2047e9728cb872adc9e64557b7a5152f-render_slice
 * @id cpp/ffmpeg/8b94df0f2047e9728cb872adc9e64557b7a5152f/render-slice
 * @description ffmpeg-8b94df0f2047e9728cb872adc9e64557b7a5152f-libavcodec/vp3.c-render_slice CVE-2011-4352
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getRValue() instanceof FunctionCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(BlockStmt target_8, Function func) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_1.getLesserOperand().(Literal).getValue()="63"
		and target_1.getParent().(IfStmt).getThen()=target_8
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(FunctionCall target_7, Function func) {
	exists(ContinueStmt target_2 |
		target_2.getParent().(IfStmt).getCondition()=target_7
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(EqualityOperation target_9, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="63"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vstride_1464, Parameter vs_1448, Variable vblock_1451, Variable vfirst_pixel_1455, Variable voutput_plane_1461, EqualityOperation target_9, ExprStmt target_10, ExprStmt target_11, PointerArithmeticOperation target_12, ValueFieldAccess target_13, FunctionCall target_7, PointerArithmeticOperation target_14, PointerArithmeticOperation target_15) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="idct_add"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dsp"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_plane_1461
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfirst_pixel_1455
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vstride_1464
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vblock_1451
		and target_4.getElse() instanceof BlockStmt
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getExpr().(VariableCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getExpr().(VariableCall).getArgument(1).(VariableAccess).getLocation())
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getArgument(4).(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getLocation())
		and target_14.getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vstride_1464, Parameter vs_1448, Variable vblock_1451, Variable vfirst_pixel_1455, Variable voutput_plane_1461, FunctionCall target_7, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="vp3_idct_dc_add"
		and target_5.getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dsp"
		and target_5.getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
		and target_5.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_plane_1461
		and target_5.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfirst_pixel_1455
		and target_5.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vstride_1464
		and target_5.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vblock_1451
		and target_5.getParent().(IfStmt).getCondition()=target_7
}

predicate func_6(Parameter vs_1448, Variable vi_1450, Variable vblock_1451, Variable vplane_1455, FunctionCall target_6) {
		target_6.getTarget().hasName("vp3_dequant")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vs_1448
		and target_6.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="all_fragments"
		and target_6.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
		and target_6.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_1450
		and target_6.getArgument(2).(VariableAccess).getTarget()=vplane_1455
		and target_6.getArgument(3).(Literal).getValue()="0"
		and target_6.getArgument(4).(VariableAccess).getTarget()=vblock_1451
}

predicate func_7(Parameter vs_1448, Variable vi_1450, Variable vblock_1451, Variable vplane_1455, BlockStmt target_8, FunctionCall target_7) {
		target_7.getTarget().hasName("vp3_dequant")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vs_1448
		and target_7.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="all_fragments"
		and target_7.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
		and target_7.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_1450
		and target_7.getArgument(2).(VariableAccess).getTarget()=vplane_1455
		and target_7.getArgument(3).(Literal).getValue()="1"
		and target_7.getArgument(4).(VariableAccess).getTarget()=vblock_1451
		and target_7.getParent().(IfStmt).getThen()=target_8
}

predicate func_8(Variable vstride_1464, Parameter vs_1448, Variable vblock_1451, Variable vfirst_pixel_1455, Variable voutput_plane_1461, BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="idct_add"
		and target_8.getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dsp"
		and target_8.getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
		and target_8.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_plane_1461
		and target_8.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfirst_pixel_1455
		and target_8.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vstride_1464
		and target_8.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vblock_1451
}

predicate func_9(Parameter vs_1448, Variable vi_1450, EqualityOperation target_9) {
		target_9.getAnOperand().(ValueFieldAccess).getTarget().getName()="coding_method"
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="all_fragments"
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1450
		and target_9.getAnOperand().(Literal).getValue()="1"
}

predicate func_10(Variable vstride_1464, Parameter vs_1448, Variable vblock_1451, Variable vfirst_pixel_1455, Variable voutput_plane_1461, ExprStmt target_10) {
		target_10.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="idct_put"
		and target_10.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dsp"
		and target_10.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
		and target_10.getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_plane_1461
		and target_10.getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfirst_pixel_1455
		and target_10.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vstride_1464
		and target_10.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vblock_1451
}

predicate func_11(Variable vstride_1464, Parameter vs_1448, Variable vblock_1451, Variable vfirst_pixel_1455, Variable voutput_plane_1461, ExprStmt target_11) {
		target_11.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="vp3_idct_dc_add"
		and target_11.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dsp"
		and target_11.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
		and target_11.getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_plane_1461
		and target_11.getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfirst_pixel_1455
		and target_11.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vstride_1464
		and target_11.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vblock_1451
}

predicate func_12(Parameter vs_1448, Variable vi_1450, PointerArithmeticOperation target_12) {
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="all_fragments"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
		and target_12.getAnOperand().(VariableAccess).getTarget()=vi_1450
}

predicate func_13(Parameter vs_1448, ValueFieldAccess target_13) {
		target_13.getTarget().getName()="vp3_idct_dc_add"
		and target_13.getQualifier().(PointerFieldAccess).getTarget().getName()="dsp"
		and target_13.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1448
}

predicate func_14(Variable vfirst_pixel_1455, Variable voutput_plane_1461, PointerArithmeticOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=voutput_plane_1461
		and target_14.getAnOperand().(VariableAccess).getTarget()=vfirst_pixel_1455
}

predicate func_15(Variable vfirst_pixel_1455, Variable voutput_plane_1461, PointerArithmeticOperation target_15) {
		target_15.getAnOperand().(VariableAccess).getTarget()=voutput_plane_1461
		and target_15.getAnOperand().(VariableAccess).getTarget()=vfirst_pixel_1455
}

from Function func, Variable vstride_1464, Parameter vs_1448, Variable vi_1450, Variable vblock_1451, Variable vplane_1455, Variable vfirst_pixel_1455, Variable voutput_plane_1461, BlockStmt target_5, FunctionCall target_6, FunctionCall target_7, BlockStmt target_8, EqualityOperation target_9, ExprStmt target_10, ExprStmt target_11, PointerArithmeticOperation target_12, ValueFieldAccess target_13, PointerArithmeticOperation target_14, PointerArithmeticOperation target_15
where
not func_0(func)
and not func_1(target_8, func)
and not func_2(target_7, func)
and not func_3(target_9, func)
and not func_4(vstride_1464, vs_1448, vblock_1451, vfirst_pixel_1455, voutput_plane_1461, target_9, target_10, target_11, target_12, target_13, target_7, target_14, target_15)
and func_5(vstride_1464, vs_1448, vblock_1451, vfirst_pixel_1455, voutput_plane_1461, target_7, target_5)
and func_6(vs_1448, vi_1450, vblock_1451, vplane_1455, target_6)
and func_7(vs_1448, vi_1450, vblock_1451, vplane_1455, target_8, target_7)
and func_8(vstride_1464, vs_1448, vblock_1451, vfirst_pixel_1455, voutput_plane_1461, target_8)
and func_9(vs_1448, vi_1450, target_9)
and func_10(vstride_1464, vs_1448, vblock_1451, vfirst_pixel_1455, voutput_plane_1461, target_10)
and func_11(vstride_1464, vs_1448, vblock_1451, vfirst_pixel_1455, voutput_plane_1461, target_11)
and func_12(vs_1448, vi_1450, target_12)
and func_13(vs_1448, target_13)
and func_14(vfirst_pixel_1455, voutput_plane_1461, target_14)
and func_15(vfirst_pixel_1455, voutput_plane_1461, target_15)
and vstride_1464.getType().hasName("int")
and vs_1448.getType().hasName("Vp3DecodeContext *")
and vi_1450.getType().hasName("int")
and vblock_1451.getType().hasName("DCTELEM[64]")
and vplane_1455.getType().hasName("int")
and vfirst_pixel_1455.getType().hasName("int")
and voutput_plane_1461.getType().hasName("uint8_t *")
and vstride_1464.(LocalVariable).getFunction() = func
and vs_1448.getFunction() = func
and vi_1450.(LocalVariable).getFunction() = func
and vblock_1451.(LocalVariable).getFunction() = func
and vplane_1455.(LocalVariable).getFunction() = func
and vfirst_pixel_1455.(LocalVariable).getFunction() = func
and voutput_plane_1461.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
