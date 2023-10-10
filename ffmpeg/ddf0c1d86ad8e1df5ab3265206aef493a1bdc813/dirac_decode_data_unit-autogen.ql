/**
 * @name ffmpeg-ddf0c1d86ad8e1df5ab3265206aef493a1bdc813-dirac_decode_data_unit
 * @id cpp/ffmpeg/ddf0c1d86ad8e1df5ab3265206aef493a1bdc813/dirac-decode-data-unit
 * @description ffmpeg-ddf0c1d86ad8e1df5ab3265206aef493a1bdc813-libavcodec/diracdec.c-dirac_decode_data_unit CVE-2011-3950
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_0.getRValue() instanceof BitwiseAndExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vavctx_1720, BitwiseAndExpr target_5, ExprStmt target_6, RelationalOperation target_7) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_1720
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="num_refs of 3\n"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getLesserOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_1722, BitwiseAndExpr target_5, ExprStmt target_8, ExprStmt target_9) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num_refs"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1722
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("unsigned int")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_8.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vs_1722, Variable vparse_code_1724, BitwiseAndExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vparse_code_1724
		and target_4.getRightOperand().(HexLiteral).getValue()="3"
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num_refs"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1722
}

predicate func_5(Variable vparse_code_1724, BitwiseAndExpr target_5) {
		target_5.getLeftOperand().(VariableAccess).getTarget()=vparse_code_1724
		and target_5.getRightOperand().(HexLiteral).getValue()="8"
}

predicate func_6(Parameter vavctx_1720, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_1720
		and target_6.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="framelist full\n"
}

predicate func_7(Parameter vavctx_1720, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="get_buffer"
		and target_7.getLesserOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1720
		and target_7.getLesserOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vavctx_1720
		and target_7.getLesserOperand().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="avframe"
		and target_7.getLesserOperand().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("DiracFrame *")
		and target_7.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_8(Variable vs_1722, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("DiracFrame *")
		and target_8.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="all_frames"
		and target_8.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1722
		and target_8.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_9(Variable vs_1722, Variable vparse_code_1724, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_arith"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1722
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vparse_code_1724
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="72"
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="8"
}

from Function func, Variable vs_1722, Variable vparse_code_1724, Parameter vavctx_1720, BitwiseAndExpr target_4, BitwiseAndExpr target_5, ExprStmt target_6, RelationalOperation target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(func)
and not func_1(vavctx_1720, target_5, target_6, target_7)
and not func_2(vs_1722, target_5, target_8, target_9)
and func_4(vs_1722, vparse_code_1724, target_4)
and func_5(vparse_code_1724, target_5)
and func_6(vavctx_1720, target_6)
and func_7(vavctx_1720, target_7)
and func_8(vs_1722, target_8)
and func_9(vs_1722, vparse_code_1724, target_9)
and vs_1722.getType().hasName("DiracContext *")
and vparse_code_1724.getType().hasName("int")
and vavctx_1720.getType().hasName("AVCodecContext *")
and vs_1722.(LocalVariable).getFunction() = func
and vparse_code_1724.(LocalVariable).getFunction() = func
and vavctx_1720.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
