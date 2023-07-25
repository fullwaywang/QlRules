/**
 * @name ffmpeg-5400e4a50c61e53e1bc50b3e77201649bbe9c510-mxf_parse_mpeg2_frame
 * @id cpp/ffmpeg/5400e4a50c61e53e1bc50b3e77201649bbe9c510/mxf-parse-mpeg2-frame
 * @description ffmpeg-5400e4a50c61e53e1bc50b3e77201649bbe9c510-libavformat/mxfenc.c-mxf_parse_mpeg2_frame CVE-2020-20450
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("const UID *")
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_0.getEnclosingFunction() = func)
}

predicate func_4(Parameter vst_2385, FunctionCall target_4) {
		target_4.getTarget().hasName("mxf_get_mpeg2_codec_ul")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="codecpar"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vst_2385
}

predicate func_5(Variable vsc_2388, NotExpr target_5) {
		target_5.getOperand().(PointerFieldAccess).getTarget().getName()="codec_ul"
		and target_5.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_2388
}

predicate func_6(EqualityOperation target_6) {
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="oformat"
}

from Function func, Parameter vst_2385, Variable vsc_2388, FunctionCall target_4, NotExpr target_5, EqualityOperation target_6
where
not func_0(target_6, func)
and func_4(vst_2385, target_4)
and func_5(vsc_2388, target_5)
and func_6(target_6)
and vst_2385.getType().hasName("AVStream *")
and vsc_2388.getType().hasName("MXFStreamContext *")
and vst_2385.getParentScope+() = func
and vsc_2388.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
