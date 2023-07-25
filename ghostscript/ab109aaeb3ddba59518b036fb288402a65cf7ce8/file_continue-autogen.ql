/**
 * @name ghostscript-ab109aaeb3ddba59518b036fb288402a65cf7ce8-file_continue
 * @id cpp/ghostscript/ab109aaeb3ddba59518b036fb288402a65cf7ce8/file-continue
 * @description ghostscript-ab109aaeb3ddba59518b036fb288402a65cf7ce8-psi/zfile.c-file_continue CVE-2013-5653
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_369, Variable vcode_370, SubExpr target_5, ExprStmt target_3, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcode_370
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ComplementExpr).getValue()="4294967295"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerSubExpr).getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerSubExpr).getRValue().(Literal).getValue()="5"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="14"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcode_370
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_369
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen() instanceof BlockStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_5.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vi_ctx_p_362, Variable vpscratch_365, Variable vdevlen_367, Variable viodev_368, Variable vcode_370, EqualityOperation target_6, ValueFieldAccess target_7, ValueFieldAccess target_8, PointerArithmeticOperation target_9, ExprStmt target_10, SubExpr target_5, ExprStmt target_11, ValueFieldAccess target_12, RelationalOperation target_13) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=viodev_368
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("gs_getiodevice")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="current"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_362
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("check_file_permissions_reduced")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_362
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="bytes"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpscratch_365
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcode_370
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdevlen_367
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(StringLiteral).getValue()="PermitFileReading"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen() instanceof BlockStmt
		and target_1.getParent().(IfStmt).getParent().(IfStmt).getElse().(IfStmt).getElse()=target_1
		and target_1.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_5.getRightOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_13.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_2(Variable vpscratch_365, Variable vdevlen_367, Variable viodev_368, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="bytes"
		and target_2.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_2.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpscratch_365
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dname"
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viodev_368
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdevlen_367
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vpscratch_365, Variable vpfen_366, Variable vdevlen_367, Variable viodev_368, Variable vlen_369, Variable vcode_370, Function func, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_370
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="enumerate_next"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viodev_368
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vpfen_366
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="bytes"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpscratch_365
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdevlen_367
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_369
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vdevlen_367
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vop_364, Variable vpscratch_365, Variable vdevlen_367, Variable vcode_370, EqualityOperation target_6, BlockStmt target_4) {
		target_4.getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vop_364
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="1"
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vop_364
		and target_4.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vop_364
		and target_4.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpscratch_365
		and target_4.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="rsize"
		and target_4.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_4.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_364
		and target_4.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcode_370
		and target_4.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdevlen_367
		and target_4.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(PrefixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="p"
		and target_4.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(PrefixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_4.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(PrefixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="exec_stack"
		and target_4.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opproc"
		and target_4.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_4.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="rsize"
		and target_4.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_4.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PrefixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="p"
		and target_4.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PrefixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_4.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpscratch_365
		and target_4.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_4.getStmt(5).(ReturnStmt).getExpr().(Literal).getValue()="5"
		and target_4.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_5(Variable vdevlen_367, Variable vlen_369, SubExpr target_5) {
		target_5.getLeftOperand().(VariableAccess).getTarget()=vlen_369
		and target_5.getRightOperand().(VariableAccess).getTarget()=vdevlen_367
}

predicate func_6(Variable vcode_370, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vcode_370
		and target_6.getAnOperand().(ComplementExpr).getValue()="4294967295"
}

predicate func_7(Parameter vi_ctx_p_362, ValueFieldAccess target_7) {
		target_7.getTarget().getName()="stack"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="exec_stack"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_362
}

predicate func_8(Parameter vi_ctx_p_362, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="stack"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_362
}

predicate func_9(Variable vpscratch_365, Variable vdevlen_367, PointerArithmeticOperation target_9) {
		target_9.getAnOperand().(ValueFieldAccess).getTarget().getName()="bytes"
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpscratch_365
		and target_9.getAnOperand().(VariableAccess).getTarget()=vdevlen_367
}

predicate func_10(Variable vop_364, Variable vpscratch_365, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vop_364
		and target_10.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpscratch_365
}

predicate func_11(Variable vop_364, Variable vdevlen_367, Variable vcode_370, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="rsize"
		and target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_364
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcode_370
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdevlen_367
}

predicate func_12(Variable viodev_368, ValueFieldAccess target_12) {
		target_12.getTarget().getName()="enumerate_next"
		and target_12.getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viodev_368
}

predicate func_13(Variable vlen_369, Variable vcode_370, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vcode_370
		and target_13.getLesserOperand().(VariableAccess).getTarget()=vlen_369
}

from Function func, Parameter vi_ctx_p_362, Variable vop_364, Variable vpscratch_365, Variable vpfen_366, Variable vdevlen_367, Variable viodev_368, Variable vlen_369, Variable vcode_370, ExprStmt target_2, ExprStmt target_3, BlockStmt target_4, SubExpr target_5, EqualityOperation target_6, ValueFieldAccess target_7, ValueFieldAccess target_8, PointerArithmeticOperation target_9, ExprStmt target_10, ExprStmt target_11, ValueFieldAccess target_12, RelationalOperation target_13
where
not func_0(vlen_369, vcode_370, target_5, target_3, func)
and func_2(vpscratch_365, vdevlen_367, viodev_368, func, target_2)
and func_3(vpscratch_365, vpfen_366, vdevlen_367, viodev_368, vlen_369, vcode_370, func, target_3)
and func_4(vop_364, vpscratch_365, vdevlen_367, vcode_370, target_6, target_4)
and func_5(vdevlen_367, vlen_369, target_5)
and func_6(vcode_370, target_6)
and func_7(vi_ctx_p_362, target_7)
and func_8(vi_ctx_p_362, target_8)
and func_9(vpscratch_365, vdevlen_367, target_9)
and func_10(vop_364, vpscratch_365, target_10)
and func_11(vop_364, vdevlen_367, vcode_370, target_11)
and func_12(viodev_368, target_12)
and func_13(vlen_369, vcode_370, target_13)
and vi_ctx_p_362.getType().hasName("i_ctx_t *")
and vop_364.getType().hasName("os_ptr")
and vpscratch_365.getType().hasName("es_ptr")
and vpfen_366.getType().hasName("file_enum *")
and vdevlen_367.getType().hasName("int")
and viodev_368.getType().hasName("gx_io_device *")
and vlen_369.getType().hasName("uint")
and vcode_370.getType().hasName("uint")
and vi_ctx_p_362.getFunction() = func
and vop_364.(LocalVariable).getFunction() = func
and vpscratch_365.(LocalVariable).getFunction() = func
and vpfen_366.(LocalVariable).getFunction() = func
and vdevlen_367.(LocalVariable).getFunction() = func
and viodev_368.(LocalVariable).getFunction() = func
and vlen_369.(LocalVariable).getFunction() = func
and vcode_370.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
