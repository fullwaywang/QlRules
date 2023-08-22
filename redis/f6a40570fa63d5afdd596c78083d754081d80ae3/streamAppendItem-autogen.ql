/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-streamAppendItem
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/streamAppendItem
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-src/t_stream.c-streamAppendItem CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(RelationalOperation target_14, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="33"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vnumfields_196, ExprStmt target_15, Function func) {
	exists(ForStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int64_t")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnumfields_196
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_1.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("int64_t")
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("sdslen")
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sds")
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getValue()="1073741824"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="34"
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_2))
}

predicate func_3(BlockStmt target_16, Function func) {
	exists(LogicalOrExpr target_3 |
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getValue()="1073741824"
		and target_3.getParent().(IfStmt).getThen()=target_16
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(LogicalAndExpr target_13, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_4.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getValue()="1073741824"
		and target_4.getParent().(IfStmt).getCondition()=target_13
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vlp_bytes_216, Variable vlp_217, EqualityOperation target_17, ExprStmt target_18, LogicalOrExpr target_19, FunctionCall target_20) {
	exists(IfStmt target_5 |
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlp_bytes_216
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlp_217
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getElse() instanceof IfStmt
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_20.getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_6(Variable vlp_bytes_216, ExprStmt target_18, LogicalOrExpr target_19) {
	exists(AddExpr target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=vlp_bytes_216
		and target_6.getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

*/
predicate func_8(Variable vserver, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="stream_node_max_bytes"
		and target_8.getQualifier().(VariableAccess).getTarget()=vserver
}

predicate func_9(Variable vlp_217, Variable vserver, Variable vcount_273, LogicalAndExpr target_13, IfStmt target_9) {
		target_9.getCondition().(ValueFieldAccess).getTarget().getName()="stream_node_max_entries"
		and target_9.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_273
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="stream_node_max_entries"
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlp_217
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getParent().(IfStmt).getCondition()=target_13
}

predicate func_10(RelationalOperation target_14, Function func, ReturnStmt target_10) {
		target_10.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_10.getParent().(IfStmt).getCondition()=target_14
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Variable vserver, ValueFieldAccess target_11) {
		target_11.getTarget().getName()="stream_node_max_bytes"
		and target_11.getQualifier().(VariableAccess).getTarget()=vserver
}

predicate func_12(Variable vlp_bytes_216, VariableAccess target_12) {
		target_12.getTarget()=vlp_bytes_216
}

predicate func_13(Variable vlp_bytes_216, BlockStmt target_16, LogicalAndExpr target_13) {
		target_13.getAnOperand() instanceof ValueFieldAccess
		and target_13.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlp_bytes_216
		and target_13.getAnOperand().(RelationalOperation).getLesserOperand() instanceof ValueFieldAccess
		and target_13.getParent().(IfStmt).getThen()=target_16
}

predicate func_14(RelationalOperation target_14) {
		 (target_14 instanceof GEExpr or target_14 instanceof LEExpr)
		and target_14.getLesserOperand().(FunctionCall).getTarget().hasName("streamCompareID")
		and target_14.getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("streamID")
		and target_14.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="last_id"
		and target_14.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("stream *")
		and target_14.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_15(Parameter vnumfields_196, Variable vlp_217, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlp_217
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lpAppendInteger")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlp_217
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnumfields_196
}

predicate func_16(Variable vlp_217, BlockStmt target_16) {
		target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlp_217
		and target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_17(Variable vlp_217, EqualityOperation target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vlp_217
		and target_17.getAnOperand().(Literal).getValue()="0"
}

predicate func_18(Variable vlp_bytes_216, Variable vlp_217, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlp_bytes_216
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lpBytes")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlp_217
}

predicate func_19(Variable vlp_bytes_216, Variable vlp_217, Variable vserver, LogicalOrExpr target_19) {
		target_19.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlp_217
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_19.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlp_bytes_216
		and target_19.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="stream_node_max_bytes"
		and target_19.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vserver
}

predicate func_20(Variable vlp_217, FunctionCall target_20) {
		target_20.getTarget().hasName("lpFirst")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vlp_217
}

from Function func, Parameter vnumfields_196, Variable vlp_bytes_216, Variable vlp_217, Variable vserver, Variable vcount_273, ValueFieldAccess target_8, IfStmt target_9, ReturnStmt target_10, ValueFieldAccess target_11, VariableAccess target_12, LogicalAndExpr target_13, RelationalOperation target_14, ExprStmt target_15, BlockStmt target_16, EqualityOperation target_17, ExprStmt target_18, LogicalOrExpr target_19, FunctionCall target_20
where
not func_0(target_14, func)
and not func_1(vnumfields_196, target_15, func)
and not func_2(func)
and not func_3(target_16, func)
and not func_4(target_13, func)
and not func_5(vlp_bytes_216, vlp_217, target_17, target_18, target_19, target_20)
and func_8(vserver, target_8)
and func_9(vlp_217, vserver, vcount_273, target_13, target_9)
and func_10(target_14, func, target_10)
and func_11(vserver, target_11)
and func_12(vlp_bytes_216, target_12)
and func_13(vlp_bytes_216, target_16, target_13)
and func_14(target_14)
and func_15(vnumfields_196, vlp_217, target_15)
and func_16(vlp_217, target_16)
and func_17(vlp_217, target_17)
and func_18(vlp_bytes_216, vlp_217, target_18)
and func_19(vlp_bytes_216, vlp_217, vserver, target_19)
and func_20(vlp_217, target_20)
and vnumfields_196.getType().hasName("int64_t")
and vlp_bytes_216.getType().hasName("size_t")
and vlp_217.getType().hasName("unsigned char *")
and vserver.getType().hasName("redisServer")
and vcount_273.getType().hasName("int64_t")
and vnumfields_196.getFunction() = func
and vlp_bytes_216.(LocalVariable).getFunction() = func
and vlp_217.(LocalVariable).getFunction() = func
and not vserver.getParentScope+() = func
and vcount_273.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
