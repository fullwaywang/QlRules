/**
 * @name ffmpeg-cced03dd667a5df6df8fd40d8de0bff477ee02e8-ff_mms_asf_header_parser
 * @id cpp/ffmpeg/cced03dd667a5df6df8fd40d8de0bff477ee02e8/ff-mms-asf-header-parser
 * @description ffmpeg-cced03dd667a5df6df8fd40d8de0bff477ee02e8-libavformat/mms.c-ff_mms_asf_header_parser CVE-2018-1999010
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmms_54, Variable vp_56, Variable vend_57, Variable vflags_58, Variable vstream_id_58, NotExpr target_3, ExprStmt target_4, LogicalAndExpr target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_57
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_56
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="74"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vflags_58
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="24"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstream_id_58
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_58
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="127"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="stream_num"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmms_54
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="46"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="512"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="streams"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_fast_realloc")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="streams"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="id"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstream_id_58
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="stream_num"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Corrupt stream (too many A/V streams)\n"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vp_56, Variable vend_57, Variable vchunksize_73, NotExpr target_3, RelationalOperation target_7, ExprStmt target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vchunksize_73
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_57
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_56
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Corrupt stream (header chunksize %ld is invalid)\n"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vchunksize_73
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_7.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vchunksize_73, NotExpr target_3, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchunksize_73
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="46"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vp_56, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_56
		and target_3.getOperand().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getOperand().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="16"
}

predicate func_4(Parameter vmms_54, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_4.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Corrupt stream (too large pkt_len %d)\n"
		and target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="asf_packet_len"
		and target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmms_54
}

predicate func_5(Parameter vmms_54, LogicalAndExpr target_5) {
		target_5.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="stream_num"
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmms_54
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="46"
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="stream_num"
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmms_54
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="6"
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="512"
}

predicate func_6(Variable vp_56, Variable vchunksize_73, ExprStmt target_6) {
		target_6.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_56
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vchunksize_73
}

predicate func_7(Variable vp_56, Variable vend_57, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_57
		and target_7.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_56
}

predicate func_8(Variable vchunksize_73, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchunksize_73
}

from Function func, Parameter vmms_54, Variable vp_56, Variable vend_57, Variable vflags_58, Variable vstream_id_58, Variable vchunksize_73, ExprStmt target_2, NotExpr target_3, ExprStmt target_4, LogicalAndExpr target_5, ExprStmt target_6, RelationalOperation target_7, ExprStmt target_8
where
not func_0(vmms_54, vp_56, vend_57, vflags_58, vstream_id_58, target_3, target_4, target_5, target_6)
and not func_1(vp_56, vend_57, vchunksize_73, target_3, target_7, target_8)
and func_2(vchunksize_73, target_3, target_2)
and func_3(vp_56, target_3)
and func_4(vmms_54, target_4)
and func_5(vmms_54, target_5)
and func_6(vp_56, vchunksize_73, target_6)
and func_7(vp_56, vend_57, target_7)
and func_8(vchunksize_73, target_8)
and vmms_54.getType().hasName("MMSContext *")
and vp_56.getType().hasName("uint8_t *")
and vend_57.getType().hasName("uint8_t *")
and vflags_58.getType().hasName("int")
and vstream_id_58.getType().hasName("int")
and vchunksize_73.getType().hasName("uint64_t")
and vmms_54.getParentScope+() = func
and vp_56.getParentScope+() = func
and vend_57.getParentScope+() = func
and vflags_58.getParentScope+() = func
and vstream_id_58.getParentScope+() = func
and vchunksize_73.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
