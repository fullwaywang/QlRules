/**
 * @name ffmpeg-5400e4a50c61e53e1bc50b3e77201649bbe9c510-mxf_parse_prores_frame
 * @id cpp/ffmpeg/5400e4a50c61e53e1bc50b3e77201649bbe9c510/mxf-parse-prores-frame
 * @description ffmpeg-5400e4a50c61e53e1bc50b3e77201649bbe9c510-libavformat/mxfenc.c-mxf_parse_prores_frame CVE-2020-20450
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_2018, ReturnStmt target_5, ArrayExpr target_6) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vi_2018
		and target_0.getAnOperand().(DivExpr).getValue()="6"
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsc_2017, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="codec_ul"
		and target_1.getQualifier().(VariableAccess).getTarget()=vsc_2017
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Variable vsc_2017, Function func, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="codec_ul"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_2017
		and target_3.getExpr().(AssignExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vsc_2017, ReturnStmt target_5, NotExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="codec_ul"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsc_2017
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(ReturnStmt target_5) {
		target_5.getExpr().(Literal).getValue()="0"
}

predicate func_6(Variable vi_2018, ArrayExpr target_6) {
		target_6.getArrayOffset().(VariableAccess).getTarget()=vi_2018
}

from Function func, Variable vsc_2017, Variable vi_2018, PointerFieldAccess target_1, ExprStmt target_3, NotExpr target_4, ReturnStmt target_5, ArrayExpr target_6
where
not func_0(vi_2018, target_5, target_6)
and func_1(vsc_2017, target_1)
and func_3(vsc_2017, func, target_3)
and func_4(vsc_2017, target_5, target_4)
and func_5(target_5)
and func_6(vi_2018, target_6)
and vsc_2017.getType().hasName("MXFStreamContext *")
and vi_2018.getType().hasName("int")
and vsc_2017.getParentScope+() = func
and vi_2018.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
