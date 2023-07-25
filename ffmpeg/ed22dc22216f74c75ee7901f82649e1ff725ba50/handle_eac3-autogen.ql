/**
 * @name ffmpeg-ed22dc22216f74c75ee7901f82649e1ff725ba50-handle_eac3
 * @id cpp/ffmpeg/ed22dc22216f74c75ee7901f82649e1ff725ba50/handle-eac3
 * @description ffmpeg-ed22dc22216f74c75ee7901f82649e1ff725ba50-libavformat/movenc.c-handle_eac3 CVE-2018-13302
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhdr_393, Variable vret_395, Parameter vmov_391, EqualityOperation target_1, LogicalOrExpr target_2, ArrayExpr target_3, ExprStmt target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="substreamid"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_393
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("avpriv_request_sample")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fc"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmov_391
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Multiple non EAC3 independent substreams"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_395
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1163346256"
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="end"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vhdr_393, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="frame_type"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_393
}

predicate func_2(Variable vhdr_393, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="substreamid"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_393
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_ind_sub"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="substreamid"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_393
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="bsid"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="substream"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_3(Variable vhdr_393, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="substream"
		and target_3.getArrayOffset().(PointerFieldAccess).getTarget().getName()="substreamid"
		and target_3.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_393
}

predicate func_4(Variable vret_395, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_395
		and target_4.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1163346256"
}

predicate func_5(Parameter vmov_391, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmov_391
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Dropping invalid packet from start of the stream\n"
}

from Function func, Variable vhdr_393, Variable vret_395, Parameter vmov_391, EqualityOperation target_1, LogicalOrExpr target_2, ArrayExpr target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vhdr_393, vret_395, vmov_391, target_1, target_2, target_3, target_4, target_5)
and func_1(vhdr_393, target_1)
and func_2(vhdr_393, target_2)
and func_3(vhdr_393, target_3)
and func_4(vret_395, target_4)
and func_5(vmov_391, target_5)
and vhdr_393.getType().hasName("AC3HeaderInfo *")
and vret_395.getType().hasName("int")
and vmov_391.getType().hasName("MOVMuxContext *")
and vhdr_393.getParentScope+() = func
and vret_395.getParentScope+() = func
and vmov_391.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
