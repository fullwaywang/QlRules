/**
 * @name util-linux-7164a1c34d18831ac61c6744ad14ce916d389b3f-parse_dos_extended
 * @id cpp/util-linux/7164a1c34d18831ac61c6744ad14ce916d389b3f/parse-dos-extended
 * @description util-linux-7164a1c34d18831ac61c6744ad14ce916d389b3f-libblkid/src/partitions/dos.c-parse_dos_extended CVE-2016-5011
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getValue()="256"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(VariableAccess).getType().hasName("int")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("FILE *")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%d: %s: %8s: "
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("getpid")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="libblkid"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="LOWPROBE"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ul_debug")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="parse EBR [start=%d, size=%d]"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

/*predicate func_1(BreakStmt target_21, Function func) {
	exists(BitwiseAndExpr target_1 |
		target_1.getLeftOperand().(BinaryBitwiseOperation).getValue()="256"
		and target_1.getRightOperand().(VariableAccess).getType().hasName("int")
		and target_1.getParent().(IfStmt).getThen()=target_21
		and target_1.getEnclosingFunction() = func)
}

*/
/*predicate func_2(LogicalAndExpr target_16, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("FILE *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%d: %s: %8s: "
		and target_2.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("getpid")
		and target_2.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="libblkid"
		and target_2.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="LOWPROBE"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_2.getEnclosingFunction() = func)
}

*/
/*predicate func_3(Parameter vex_start_42, Parameter vex_size_42, Parameter vssf_42, LogicalAndExpr target_16, RelationalOperation target_22, ExprStmt target_18, ExprStmt target_15) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("ul_debug")
		and target_3.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="parse EBR [start=%d, size=%d]"
		and target_3.getExpr().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vex_start_42
		and target_3.getExpr().(FunctionCall).getArgument(1).(DivExpr).getRightOperand().(VariableAccess).getTarget()=vssf_42
		and target_3.getExpr().(FunctionCall).getArgument(2).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vex_size_42
		and target_3.getExpr().(FunctionCall).getArgument(2).(DivExpr).getRightOperand().(VariableAccess).getTarget()=vssf_42
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_22.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(1).(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(DivExpr).getRightOperand().(VariableAccess).getLocation()))
}

*/
predicate func_4(Parameter vex_start_42, RelationalOperation target_23, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vex_start_42
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(VariableAccess).getType().hasName("int")
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_4)
		and target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_23.getGreaterOperand().(VariableAccess).getLocation()))
}

/*predicate func_5(Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getValue()="256"
		and target_5.getCondition().(BitwiseAndExpr).getRightOperand().(VariableAccess).getType().hasName("int")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("FILE *")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%d: %s: %8s: "
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("getpid")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="libblkid"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="LOWPROBE"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ul_debug")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Bad offset in primary extended partition -- ignore"
		and target_5.getEnclosingFunction() = func)
}

*/
predicate func_6(Variable vstart_52, RelationalOperation target_24) {
	exists(IfStmt target_6 |
		target_6.getCondition() instanceof LogicalAndExpr
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstart_52
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse() instanceof BreakStmt
		and target_24.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_9(Variable vct_nodata_47, IfStmt target_9) {
		target_9.getCondition().(RelationalOperation).getGreaterOperand().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vct_nodata_47
		and target_9.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="100"
		and target_9.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_10(Parameter vpr_41, Variable vcur_start_45, Variable vdata_46, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdata_46
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("blkid_probe_get_sector")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpr_41
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcur_start_45
}

predicate func_11(Variable vdata_46, IfStmt target_11) {
		target_11.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vdata_46
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_11.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_11.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="leave"
}

predicate func_12(Variable vdata_46, IfStmt target_12) {
		target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("mbr_is_valid_magic")
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_46
		and target_12.getThen().(GotoStmt).toString() = "goto ..."
		and target_12.getThen().(GotoStmt).getName() ="leave"
}

predicate func_13(Variable vdata_46, Variable vp0_51, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp0_51
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mbr_get_partition")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_46
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_14(Parameter vssf_42, Variable vp_51, Variable vstart_52, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_52
		and target_14.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(FunctionCall).getTarget().hasName("dos_partition_get_start")
		and target_14.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_51
		and target_14.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vssf_42
}

predicate func_15(Parameter vssf_42, Variable vp_51, Variable vsize_52, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_52
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(FunctionCall).getTarget().hasName("dos_partition_get_size")
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_51
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vssf_42
}

predicate func_16(Variable vp_51, Variable vsize_52, BreakStmt target_21, LogicalAndExpr target_16) {
		target_16.getAnOperand().(VariableAccess).getTarget()=vsize_52
		and target_16.getAnOperand().(FunctionCall).getTarget().hasName("is_extended")
		and target_16.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_51
		and target_16.getParent().(IfStmt).getThen()=target_21
}

predicate func_17(Variable vi_48, IfStmt target_17) {
		target_17.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_48
		and target_17.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_17.getThen().(GotoStmt).toString() = "goto ..."
		and target_17.getThen().(GotoStmt).getName() ="leave"
}

predicate func_18(Parameter vex_start_42, Variable vcur_start_45, Variable vstart_52, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_start_45
		and target_18.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vex_start_42
		and target_18.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstart_52
}

predicate func_19(Variable vcur_size_45, Variable vsize_52, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_size_45
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsize_52
}

predicate func_20(Parameter vtab_41, Parameter vssf_42, Variable vls_44, Variable vcur_start_45, Variable vct_nodata_47, Variable vi_48, Variable vp_51, Variable vp0_51, Variable vstart_52, Variable vsize_52, Variable vabs_start_81, Variable vpar_82, ForStmt target_20) {
		target_20.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_51
		and target_20.getInitialization().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp0_51
		and target_20.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_48
		and target_20.getInitialization().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_48
		and target_20.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_20.getUpdate().(CommaExpr).getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_48
		and target_20.getUpdate().(CommaExpr).getRightOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_51
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_52
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(FunctionCall).getTarget().hasName("dos_partition_get_start")
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vssf_42
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_52
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(FunctionCall).getTarget().hasName("dos_partition_get_size")
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vssf_42
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vabs_start_81
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcur_start_45
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstart_52
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vsize_52
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("is_extended")
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_51
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_48
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpar_82
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("blkid_partlist_add_partition")
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vls_44
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtab_41
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vabs_start_81
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsize_52
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(8).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vpar_82
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(8).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(9).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("blkid_partition_set_type")
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(9).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpar_82
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(9).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="sys_ind"
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(9).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_51
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(10).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("blkid_partition_set_flags")
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(10).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpar_82
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(10).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="boot_ind"
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(10).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_51
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(11).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("blkid_partition_gen_uuid")
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(11).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpar_82
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(12).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vct_nodata_47
		and target_20.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(12).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_20.getStmt().(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
}

predicate func_21(LogicalAndExpr target_16, Function func, BreakStmt target_21) {
		target_21.toString() = "break;"
		and target_21.getParent().(IfStmt).getCondition()=target_16
		and target_21.getEnclosingFunction() = func
}

predicate func_22(Parameter vex_start_42, Parameter vex_size_42, Variable vsize_52, Variable vabs_start_81, RelationalOperation target_22) {
		 (target_22 instanceof GTExpr or target_22 instanceof LTExpr)
		and target_22.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vabs_start_81
		and target_22.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_52
		and target_22.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vex_start_42
		and target_22.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vex_size_42
}

predicate func_23(Parameter vex_start_42, Variable vabs_start_81, RelationalOperation target_23) {
		 (target_23 instanceof GTExpr or target_23 instanceof LTExpr)
		and target_23.getLesserOperand().(VariableAccess).getTarget()=vabs_start_81
		and target_23.getGreaterOperand().(VariableAccess).getTarget()=vex_start_42
}

predicate func_24(Variable vcur_size_45, Variable vstart_52, Variable vsize_52, RelationalOperation target_24) {
		 (target_24 instanceof GTExpr or target_24 instanceof LTExpr)
		and target_24.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstart_52
		and target_24.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_52
		and target_24.getLesserOperand().(VariableAccess).getTarget()=vcur_size_45
}

from Function func, Parameter vtab_41, Parameter vpr_41, Parameter vex_start_42, Parameter vex_size_42, Parameter vssf_42, Variable vls_44, Variable vcur_start_45, Variable vcur_size_45, Variable vdata_46, Variable vct_nodata_47, Variable vi_48, Variable vp_51, Variable vp0_51, Variable vstart_52, Variable vsize_52, Variable vabs_start_81, Variable vpar_82, IfStmt target_9, ExprStmt target_10, IfStmt target_11, IfStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, LogicalAndExpr target_16, IfStmt target_17, ExprStmt target_18, ExprStmt target_19, ForStmt target_20, BreakStmt target_21, RelationalOperation target_22, RelationalOperation target_23, RelationalOperation target_24
where
not func_0(func)
and not func_4(vex_start_42, target_23, func)
and not func_6(vstart_52, target_24)
and func_9(vct_nodata_47, target_9)
and func_10(vpr_41, vcur_start_45, vdata_46, target_10)
and func_11(vdata_46, target_11)
and func_12(vdata_46, target_12)
and func_13(vdata_46, vp0_51, target_13)
and func_14(vssf_42, vp_51, vstart_52, target_14)
and func_15(vssf_42, vp_51, vsize_52, target_15)
and func_16(vp_51, vsize_52, target_21, target_16)
and func_17(vi_48, target_17)
and func_18(vex_start_42, vcur_start_45, vstart_52, target_18)
and func_19(vcur_size_45, vsize_52, target_19)
and func_20(vtab_41, vssf_42, vls_44, vcur_start_45, vct_nodata_47, vi_48, vp_51, vp0_51, vstart_52, vsize_52, vabs_start_81, vpar_82, target_20)
and func_21(target_16, func, target_21)
and func_22(vex_start_42, vex_size_42, vsize_52, vabs_start_81, target_22)
and func_23(vex_start_42, vabs_start_81, target_23)
and func_24(vcur_size_45, vstart_52, vsize_52, target_24)
and vtab_41.getType().hasName("blkid_parttable")
and vpr_41.getType().hasName("blkid_probe")
and vex_start_42.getType().hasName("uint32_t")
and vex_size_42.getType().hasName("uint32_t")
and vssf_42.getType().hasName("int")
and vls_44.getType().hasName("blkid_partlist")
and vcur_start_45.getType().hasName("uint32_t")
and vcur_size_45.getType().hasName("uint32_t")
and vdata_46.getType().hasName("unsigned char *")
and vct_nodata_47.getType().hasName("int")
and vi_48.getType().hasName("int")
and vp_51.getType().hasName("dos_partition *")
and vp0_51.getType().hasName("dos_partition *")
and vstart_52.getType().hasName("uint32_t")
and vsize_52.getType().hasName("uint32_t")
and vabs_start_81.getType().hasName("uint32_t")
and vpar_82.getType().hasName("blkid_partition")
and vtab_41.getParentScope+() = func
and vpr_41.getParentScope+() = func
and vex_start_42.getParentScope+() = func
and vex_size_42.getParentScope+() = func
and vssf_42.getParentScope+() = func
and vls_44.getParentScope+() = func
and vcur_start_45.getParentScope+() = func
and vcur_size_45.getParentScope+() = func
and vdata_46.getParentScope+() = func
and vct_nodata_47.getParentScope+() = func
and vi_48.getParentScope+() = func
and vp_51.getParentScope+() = func
and vp0_51.getParentScope+() = func
and vstart_52.getParentScope+() = func
and vsize_52.getParentScope+() = func
and vabs_start_81.getParentScope+() = func
and vpar_82.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
