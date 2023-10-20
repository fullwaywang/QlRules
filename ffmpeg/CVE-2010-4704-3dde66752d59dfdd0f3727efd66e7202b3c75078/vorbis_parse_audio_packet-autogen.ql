/**
 * @name ffmpeg-3dde66752d59dfdd0f3727efd66e7202b3c75078-vorbis_parse_audio_packet
 * @id cpp/ffmpeg/3dde66752d59dfdd0f3727efd66e7202b3c75078/vorbis-parse-audio-packet
 * @description ffmpeg-3dde66752d59dfdd0f3727efd66e7202b3c75078-libavcodec/vorbis_dec.c-vorbis_parse_audio_packet CVE-2010-4704
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getRValue() instanceof VariableCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vvc_1459, RelationalOperation target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avccontext"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvc_1459
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid codebook in vorbis_floor_decode.\n"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vi_1467, Variable vno_residue_1468, ExprStmt target_7, NotExpr target_8) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vno_residue_1468
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1467
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_8.getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_4(Variable vfloor_1504, Parameter vvc_1459, Variable vch_floor_ptr_1472, VariableCall target_4) {
		target_4.getExpr().(PointerFieldAccess).getTarget().getName()="decode"
		and target_4.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfloor_1504
		and target_4.getArgument(0).(VariableAccess).getTarget()=vvc_1459
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfloor_1504
		and target_4.getArgument(2).(VariableAccess).getTarget()=vch_floor_ptr_1472
}

predicate func_6(Parameter vvc_1459, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int_fast32_t")
		and target_6.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="audio_channels"
		and target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvc_1459
}

predicate func_7(Variable vfloor_1504, Parameter vvc_1459, Variable vi_1467, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfloor_1504
		and target_7.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="floors"
		and target_7.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvc_1459
		and target_7.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="submap_floor"
		and target_7.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("vorbis_mapping *")
		and target_7.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="mux"
		and target_7.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1467
}

predicate func_8(Variable vi_1467, Variable vno_residue_1468, NotExpr target_8) {
		target_8.getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vno_residue_1468
		and target_8.getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="magnitude"
		and target_8.getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("vorbis_mapping *")
		and target_8.getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1467
		and target_8.getOperand().(BitwiseAndExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vno_residue_1468
		and target_8.getOperand().(BitwiseAndExpr).getRightOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="angle"
		and target_8.getOperand().(BitwiseAndExpr).getRightOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("vorbis_mapping *")
		and target_8.getOperand().(BitwiseAndExpr).getRightOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1467
}

from Function func, Variable vfloor_1504, Parameter vvc_1459, Variable vi_1467, Variable vno_residue_1468, Variable vch_floor_ptr_1472, VariableCall target_4, RelationalOperation target_6, ExprStmt target_7, NotExpr target_8
where
not func_0(func)
and not func_1(vvc_1459, target_6)
and not func_2(vi_1467, vno_residue_1468, target_7, target_8)
and func_4(vfloor_1504, vvc_1459, vch_floor_ptr_1472, target_4)
and func_6(vvc_1459, target_6)
and func_7(vfloor_1504, vvc_1459, vi_1467, target_7)
and func_8(vi_1467, vno_residue_1468, target_8)
and vfloor_1504.getType().hasName("vorbis_floor *")
and vvc_1459.getType().hasName("vorbis_context *")
and vi_1467.getType().hasName("int_fast32_t")
and vno_residue_1468.getType().hasName("uint_fast8_t[255]")
and vch_floor_ptr_1472.getType().hasName("float *")
and vfloor_1504.(LocalVariable).getFunction() = func
and vvc_1459.getFunction() = func
and vi_1467.(LocalVariable).getFunction() = func
and vno_residue_1468.(LocalVariable).getFunction() = func
and vch_floor_ptr_1472.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
