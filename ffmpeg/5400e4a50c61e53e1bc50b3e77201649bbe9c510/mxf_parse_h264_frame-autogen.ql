/**
 * @name ffmpeg-5400e4a50c61e53e1bc50b3e77201649bbe9c510-mxf_parse_h264_frame
 * @id cpp/ffmpeg/5400e4a50c61e53e1bc50b3e77201649bbe9c510/mxf-parse-h264-frame
 * @description ffmpeg-5400e4a50c61e53e1bc50b3e77201649bbe9c510-libavformat/mxfenc.c-mxf_parse_h264_frame CVE-2020-20450
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Variable vsc_2242, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="codec_ul"
		and target_4.getQualifier().(VariableAccess).getTarget()=vsc_2242
		and target_4.getParent().(AssignExpr).getLValue() = target_4
		and target_4.getParent().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_5(Variable vsc_2242, Variable vi_2250, Variable vmxf_h264_codec_uls, AddressOfExpr target_5) {
		target_5.getOperand().(ValueFieldAccess).getTarget().getName()="uid"
		and target_5.getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmxf_h264_codec_uls
		and target_5.getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2250
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="codec_ul"
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_2242
}

predicate func_6(Variable vsc_2242, Variable vi_2250, Variable vmxf_h264_codec_uls, AddressOfExpr target_6) {
		target_6.getOperand().(ValueFieldAccess).getTarget().getName()="uid"
		and target_6.getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmxf_h264_codec_uls
		and target_6.getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2250
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="codec_ul"
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_2242
}

predicate func_8(Variable vsc_2242, LogicalAndExpr target_11, ExprStmt target_12, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="codec_ul"
		and target_8.getQualifier().(VariableAccess).getTarget()=vsc_2242
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getQualifier().(VariableAccess).getLocation())
		and target_8.getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_9(Variable vsc_2242, ExprStmt target_13, NotExpr target_14, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="codec_ul"
		and target_9.getQualifier().(VariableAccess).getTarget()=vsc_2242
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getQualifier().(VariableAccess).getLocation())
		and target_9.getQualifier().(VariableAccess).getLocation().isBefore(target_14.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_10(Variable vsc_2242, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="codec_ul"
		and target_10.getQualifier().(VariableAccess).getTarget()=vsc_2242
}

predicate func_11(Variable vsc_2242, Variable vi_2250, Variable vmxf_h264_codec_uls, LogicalAndExpr target_11) {
		target_11.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="frame_size"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmxf_h264_codec_uls
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2250
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="interlaced"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_2242
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="interlaced"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmxf_h264_codec_uls
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2250
}

predicate func_12(Variable vsc_2242, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="component_depth"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_2242
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="10"
}

predicate func_13(Variable vsc_2242, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="field_dominance"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_2242
		and target_13.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_14(Variable vsc_2242, NotExpr target_14) {
		target_14.getOperand().(PointerFieldAccess).getTarget().getName()="codec_ul"
		and target_14.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_2242
}

from Function func, Variable vsc_2242, Variable vi_2250, Variable vmxf_h264_codec_uls, PointerFieldAccess target_4, AddressOfExpr target_5, AddressOfExpr target_6, PointerFieldAccess target_8, PointerFieldAccess target_9, PointerFieldAccess target_10, LogicalAndExpr target_11, ExprStmt target_12, ExprStmt target_13, NotExpr target_14
where
func_4(vsc_2242, target_4)
and func_5(vsc_2242, vi_2250, vmxf_h264_codec_uls, target_5)
and func_6(vsc_2242, vi_2250, vmxf_h264_codec_uls, target_6)
and func_8(vsc_2242, target_11, target_12, target_8)
and func_9(vsc_2242, target_13, target_14, target_9)
and func_10(vsc_2242, target_10)
and func_11(vsc_2242, vi_2250, vmxf_h264_codec_uls, target_11)
and func_12(vsc_2242, target_12)
and func_13(vsc_2242, target_13)
and func_14(vsc_2242, target_14)
and vsc_2242.getType().hasName("MXFStreamContext *")
and vi_2250.getType().hasName("int")
and vmxf_h264_codec_uls.getType() instanceof ArrayType
and vsc_2242.getParentScope+() = func
and vi_2250.getParentScope+() = func
and not vmxf_h264_codec_uls.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
