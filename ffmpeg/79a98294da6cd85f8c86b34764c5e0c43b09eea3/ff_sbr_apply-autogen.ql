/**
 * @name ffmpeg-79a98294da6cd85f8c86b34764c5e0c43b09eea3-ff_sbr_apply
 * @id cpp/ffmpeg/79a98294da6cd85f8c86b34764c5e0c43b09eea3/ff-sbr-apply
 * @description ffmpeg-79a98294da6cd85f8c86b34764c5e0c43b09eea3-libavcodec/aacsbr.c-ff_sbr_apply CVE-2015-6820
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vac_1690, Parameter vsbr_1690, Parameter vid_aac_1690, ArrayExpr target_1, ExprStmt target_2, RelationalOperation target_3, NotExpr target_4, ConditionalExpr target_5, ExprStmt target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vid_aac_1690
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="id_aac"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vac_1690
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="element type mismatch %d != %d\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vid_aac_1690
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="id_aac"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sbr_turnoff")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbr_1690
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vac_1690, ArrayExpr target_1) {
		target_1.getArrayBase().(PointerFieldAccess).getTarget().getName()="oc"
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vac_1690
		and target_1.getArrayOffset().(Literal).getValue()="1"
}

predicate func_2(Parameter vac_1690, Parameter vsbr_1690, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("sbr_qmf_analysis")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fdsp"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vac_1690
		and target_2.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mdct_ana"
		and target_2.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
		and target_2.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dsp"
		and target_2.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
		and target_2.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(VariableAccess).getTarget().getType().hasName("float *")
		and target_2.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(VariableAccess).getTarget().getType().hasName("float *")
		and target_2.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="analysis_filterbank_samples"
		and target_2.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
		and target_2.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="qmf_filter_scratch"
		and target_2.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
		and target_2.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getTarget().getName()="W"
		and target_2.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
		and target_2.getExpr().(FunctionCall).getArgument(6).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getTarget().getName()="Ypos"
		and target_2.getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
		and target_2.getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Parameter vac_1690, Parameter vsbr_1690, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(ValueFieldAccess).getTarget().getName()="ext_sample_rate"
		and target_3.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="m4ac"
		and target_3.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="oc"
		and target_3.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vac_1690
		and target_3.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="sample_rate"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
}

predicate func_4(Parameter vsbr_1690, NotExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="kx_and_m_pushed"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1690
}

predicate func_5(Parameter vid_aac_1690, ConditionalExpr target_5) {
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vid_aac_1690
		and target_5.getThen().(Literal).getValue()="2"
		and target_5.getElse().(Literal).getValue()="1"
}

predicate func_6(Parameter vsbr_1690, Parameter vid_aac_1690, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("sbr_dequant")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbr_1690
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vid_aac_1690
}

from Function func, Parameter vac_1690, Parameter vsbr_1690, Parameter vid_aac_1690, ArrayExpr target_1, ExprStmt target_2, RelationalOperation target_3, NotExpr target_4, ConditionalExpr target_5, ExprStmt target_6
where
not func_0(vac_1690, vsbr_1690, vid_aac_1690, target_1, target_2, target_3, target_4, target_5, target_6, func)
and func_1(vac_1690, target_1)
and func_2(vac_1690, vsbr_1690, target_2)
and func_3(vac_1690, vsbr_1690, target_3)
and func_4(vsbr_1690, target_4)
and func_5(vid_aac_1690, target_5)
and func_6(vsbr_1690, vid_aac_1690, target_6)
and vac_1690.getType().hasName("AACContext *")
and vsbr_1690.getType().hasName("SpectralBandReplication *")
and vid_aac_1690.getType().hasName("int")
and vac_1690.getFunction() = func
and vsbr_1690.getFunction() = func
and vid_aac_1690.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
