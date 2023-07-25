/**
 * @name ffmpeg-2b46ebdbff1d8dec7a3d8ea280a612b91a582869-parse_video_info
 * @id cpp/ffmpeg/2b46ebdbff1d8dec7a3d8ea280a612b91a582869/parse-video-info
 * @description ffmpeg-2b46ebdbff1d8dec7a3d8ea280a612b91a582869-libavformat/asfdec_o.c-parse_video_info CVE-2018-1999011
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsize_bmp_697, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_bmp_697
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="2147483583"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsize_bmp_697, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vsize_bmp_697
		and target_1.getLesserOperand().(Literal).getValue()="40"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vsize_bmp_697, BlockStmt target_2) {
		target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extradata_size"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codecpar"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_bmp_697
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="40"
		and target_2.getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_2.getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codecpar"
		and target_2.getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_2.getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="extradata_size"
		and target_2.getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="64"
		and target_2.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extradata_size"
		and target_2.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codecpar"
		and target_2.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
}

predicate func_3(Variable vsize_bmp_697, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_bmp_697
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_bmp_697
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vsize_bmp_697
}

from Function func, Variable vsize_bmp_697, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vsize_bmp_697, target_2, target_3, target_1)
and func_1(vsize_bmp_697, target_2, target_1)
and func_2(vsize_bmp_697, target_2)
and func_3(vsize_bmp_697, target_3)
and vsize_bmp_697.getType().hasName("uint32_t")
and vsize_bmp_697.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
