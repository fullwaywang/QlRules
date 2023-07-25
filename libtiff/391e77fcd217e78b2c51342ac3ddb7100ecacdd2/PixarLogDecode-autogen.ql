/**
 * @name libtiff-391e77fcd217e78b2c51342ac3ddb7100ecacdd2-PixarLogDecode
 * @id cpp/libtiff/391e77fcd217e78b2c51342ac3ddb7100ecacdd2/PixarLogDecode
 * @description libtiff-391e77fcd217e78b2c51342ac3ddb7100ecacdd2-libtiff/tif_pixarlog.c-PixarLogDecode CVE-2016-5315
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmodule_743, Variable vsp_745, Parameter vtif_741, ExprStmt target_1, ExprStmt target_2, EqualityOperation target_3, RelationalOperation target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="avail_out"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="stream"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_745
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="tbuf_size"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_745
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_741
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_743
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="sp->stream.avail_out > sp->tbuf_size"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vmodule_743, Parameter vtif_741, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_741
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_743
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ZLib cannot deal with buffers this size"
}

predicate func_2(Variable vmodule_743, Variable vsp_745, Parameter vtif_741, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_741
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_743
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Decoding error at scanline %lu, %s"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tif_row"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_741
		and target_2.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="msg"
		and target_2.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="stream"
		and target_2.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_745
		and target_2.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(ValueFieldAccess).getTarget().getName()="msg"
		and target_2.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="stream"
		and target_2.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_745
		and target_2.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(StringLiteral).getValue()="(null)"
}

predicate func_3(Variable vsp_745, EqualityOperation target_3) {
		target_3.getAnOperand().(ValueFieldAccess).getTarget().getName()="avail_out"
		and target_3.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="stream"
		and target_3.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_745
		and target_3.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_3.getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="2"
}

predicate func_4(Variable vsp_745, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="avail_out"
		and target_4.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="stream"
		and target_4.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_745
		and target_4.getLesserOperand().(Literal).getValue()="0"
}

from Function func, Variable vmodule_743, Variable vsp_745, Parameter vtif_741, ExprStmt target_1, ExprStmt target_2, EqualityOperation target_3, RelationalOperation target_4
where
not func_0(vmodule_743, vsp_745, vtif_741, target_1, target_2, target_3, target_4, func)
and func_1(vmodule_743, vtif_741, target_1)
and func_2(vmodule_743, vsp_745, vtif_741, target_2)
and func_3(vsp_745, target_3)
and func_4(vsp_745, target_4)
and vmodule_743.getType().hasName("const char[]")
and vsp_745.getType().hasName("PixarLogState *")
and vtif_741.getType().hasName("TIFF *")
and vmodule_743.(LocalVariable).getFunction() = func
and vsp_745.(LocalVariable).getFunction() = func
and vtif_741.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
