/**
 * @name ffmpeg-1e42736b95065c69a7481d0cf55247024f54b660-cdxl_decode_frame
 * @id cpp/ffmpeg/1e42736b95065c69a7481d0cf55247024f54b660/cdxl-decode-frame
 * @description ffmpeg-1e42736b95065c69a7481d0cf55247024f54b660-libavcodec/cdxl.c-cdxl_decode_frame CVE-2017-9996
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_242, BlockStmt target_2, LogicalAndExpr target_3, LogicalAndExpr target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="format"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="32"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc_242, Variable vencoding_244, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vencoding_244
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="6"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vc_242, BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="palette_size"
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

predicate func_3(Variable vc_242, Variable vencoding_244, LogicalAndExpr target_3) {
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vencoding_244
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="palette_size"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="format"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="32"
}

from Function func, Variable vc_242, Variable vencoding_244, LogicalAndExpr target_1, BlockStmt target_2, LogicalAndExpr target_3
where
not func_0(vc_242, target_2, target_3, target_1)
and func_1(vc_242, vencoding_244, target_2, target_1)
and func_2(vc_242, target_2)
and func_3(vc_242, vencoding_244, target_3)
and vc_242.getType().hasName("CDXLVideoContext *")
and vencoding_244.getType().hasName("int")
and vc_242.getParentScope+() = func
and vencoding_244.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
