/**
 * @name ffmpeg-7357ca900efcf829de4cce4cec6ddc286526d417-old_codec47
 * @id cpp/ffmpeg/7357ca900efcf829de4cce4cec6ddc286526d417/old-codec47
 * @description ffmpeg-7357ca900efcf829de4cce4cec6ddc286526d417-libavcodec/sanm.c-old_codec47 CVE-2013-0863
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_623, Parameter vtop_623, Parameter vleft_624, Parameter vheight_624, Variable vstride_627, Variable vdecoded_size_631, AddressOfExpr target_1, AddressOfExpr target_2, PointerArithmeticOperation target_3, MulExpr target_4, ExprStmt target_5, FunctionCall target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdecoded_size_631
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vheight_624
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vstride_627
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vleft_624
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtop_623
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vstride_627
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdecoded_size_631
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vleft_624
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtop_623
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vstride_627
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_623
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="decoded size is too large\n"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_0)
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_4.getRightOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctx_623, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_623
}

predicate func_2(Parameter vctx_623, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_623
}

predicate func_3(Parameter vctx_623, Parameter vtop_623, Parameter vleft_624, Variable vstride_627, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="frm0"
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_623
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vleft_624
		and target_3.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtop_623
		and target_3.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vstride_627
}

predicate func_4(Parameter vctx_623, Variable vstride_627, MulExpr target_4) {
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_623
		and target_4.getRightOperand().(VariableAccess).getTarget()=vstride_627
}

predicate func_5(Parameter vctx_623, Variable vdecoded_size_631, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdecoded_size_631
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream2_get_le32")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_623
}

predicate func_6(Parameter vctx_623, Variable vdecoded_size_631, FunctionCall target_6) {
		target_6.getTarget().hasName("rle_decode")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vctx_623
		and target_6.getArgument(1).(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_6.getArgument(2).(VariableAccess).getTarget()=vdecoded_size_631
}

from Function func, Parameter vctx_623, Parameter vtop_623, Parameter vleft_624, Parameter vheight_624, Variable vstride_627, Variable vdecoded_size_631, AddressOfExpr target_1, AddressOfExpr target_2, PointerArithmeticOperation target_3, MulExpr target_4, ExprStmt target_5, FunctionCall target_6
where
not func_0(vctx_623, vtop_623, vleft_624, vheight_624, vstride_627, vdecoded_size_631, target_1, target_2, target_3, target_4, target_5, target_6, func)
and func_1(vctx_623, target_1)
and func_2(vctx_623, target_2)
and func_3(vctx_623, vtop_623, vleft_624, vstride_627, target_3)
and func_4(vctx_623, vstride_627, target_4)
and func_5(vctx_623, vdecoded_size_631, target_5)
and func_6(vctx_623, vdecoded_size_631, target_6)
and vctx_623.getType().hasName("SANMVideoContext *")
and vtop_623.getType().hasName("int")
and vleft_624.getType().hasName("int")
and vheight_624.getType().hasName("int")
and vstride_627.getType().hasName("int")
and vdecoded_size_631.getType().hasName("uint32_t")
and vctx_623.getFunction() = func
and vtop_623.getFunction() = func
and vleft_624.getFunction() = func
and vheight_624.getFunction() = func
and vstride_627.(LocalVariable).getFunction() = func
and vdecoded_size_631.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
