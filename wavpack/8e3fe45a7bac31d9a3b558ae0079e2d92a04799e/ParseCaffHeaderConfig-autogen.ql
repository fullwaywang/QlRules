/**
 * @name wavpack-8e3fe45a7bac31d9a3b558ae0079e2d92a04799e-ParseCaffHeaderConfig
 * @id cpp/wavpack/8e3fe45a7bac31d9a3b558ae0079e2d92a04799e/ParseCaffHeaderConfig
 * @description wavpack-8e3fe45a7bac31d9a3b558ae0079e2d92a04799e-cli/caff.c-ParseCaffHeaderConfig CVE-2018-7254
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vbcount_155, Variable vcaf_chunk_header_160, Parameter vinfile_153, Variable vcaf_channel_layout_277, BlockStmt target_16, ValueFieldAccess target_17, LogicalOrExpr target_18) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_1.getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_1.getLesserOperand().(Literal).getValue()="1024"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfile_153
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbcount_155
		and target_1.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_16
		and target_17.getQualifier().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(LogicalOrExpr target_18, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_2.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="this .CAF file has an invalid 'chan' chunk!"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(LogicalOrExpr target_18, Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vcaf_chunk_header_160, Variable vdebug_logging_mode, NotExpr target_19, ValueFieldAccess target_20, LogicalOrExpr target_21, IfStmt target_22, IfStmt target_23) {
	exists(IfStmt target_4 |
		target_4.getCondition().(VariableAccess).getTarget()=vdebug_logging_mode
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="'chan' chunk is %d bytes"
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_20.getQualifier().(VariableAccess).getLocation().isBefore(target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_22.getCondition().(VariableAccess).getLocation().isBefore(target_4.getCondition().(VariableAccess).getLocation())
		and target_4.getCondition().(VariableAccess).getLocation().isBefore(target_23.getCondition().(VariableAccess).getLocation()))
}

predicate func_5(Variable vcaf_channel_layout_277, NotExpr target_19, ExprStmt target_24, ExprStmt target_25) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_5.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Variable vbcount_155, Variable vcaf_chunk_header_160, Parameter vinfile_153, Parameter vinfilename_153, Variable vcaf_channel_layout_277, NotExpr target_19, LogicalOrExpr target_26, LogicalOrExpr target_18, LogicalOrExpr target_27, ExprStmt target_28, ExprStmt target_29, LogicalAndExpr target_30) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfile_153
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbcount_155
		and target_6.getCondition().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .CAF file!"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_153
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_6.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_6.getElse() instanceof IfStmt
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_27.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_28.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_29.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_30.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_7(Variable vcaf_chunk_header_160, Parameter vinfilename_153, NotExpr target_31, ValueFieldAccess target_32, ArrayExpr target_33, ExprStmt target_34) {
	exists(IfStmt target_7 |
		target_7.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_7.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_7.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_7.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_7.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_7.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1048576"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .CAF file!"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_153
		and target_7.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_32.getQualifier().(VariableAccess).getLocation().isBefore(target_7.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_33.getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_34.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_8(Variable vbuff_499, NotExpr target_31, LogicalOrExpr target_35) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuff_499
		and target_8.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_35.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_9(Variable vbcount_155, Variable vcaf_chunk_header_160, Parameter vinfile_153, Variable vcaf_channel_layout_277, BlockStmt target_16, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vbcount_155
		and target_9.getAnOperand().(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofTypeOperator).getValue()="12"
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfile_153
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_9.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbcount_155
		and target_9.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_16
}

predicate func_10(Parameter vwpc_153, Parameter vconfig_153, Variable vcaf_chunk_header_160, Variable vcaf_channel_layout_277, LogicalOrExpr target_18, IfStmt target_10) {
		target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="qmode"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_153
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("WavpackAddWrapper")
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwpc_153
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("WavpackGetErrorMessage")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwpc_153
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_10.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_10.getParent().(IfStmt).getCondition()=target_18
}

predicate func_11(Variable vcaf_chunk_header_160, FunctionCall target_11) {
		target_11.getTarget().hasName("malloc")
		and target_11.getArgument(0).(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_11.getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
}

/*predicate func_12(Variable vcaf_chunk_header_160, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getLesserOperand().(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_12.getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_12.getGreaterOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_12.getGreaterOperand().(SizeofTypeOperator).getValue()="12"
}

*/
predicate func_13(Variable vbytes_to_copy_498, FunctionCall target_13) {
		target_13.getTarget().hasName("malloc")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vbytes_to_copy_498
}

predicate func_14(Function func, Initializer target_14) {
		target_14.getExpr() instanceof FunctionCall
		and target_14.getExpr().getEnclosingFunction() = func
}

predicate func_15(Function func, Initializer target_15) {
		target_15.getExpr() instanceof FunctionCall
		and target_15.getExpr().getEnclosingFunction() = func
}

predicate func_16(Parameter vinfilename_153, Variable vcaf_channel_layout_277, BlockStmt target_16) {
		target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .CAF file!"
		and target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_153
		and target_16.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_16.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcaf_channel_layout_277
}

predicate func_17(Variable vcaf_chunk_header_160, ValueFieldAccess target_17) {
		target_17.getTarget().getName()="mChunkSize"
		and target_17.getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
}

predicate func_18(Variable vbcount_155, Variable vcaf_chunk_header_160, Parameter vinfile_153, Variable vcaf_channel_layout_277, LogicalOrExpr target_18) {
		target_18.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfile_153
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_18.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbcount_155
		and target_18.getAnOperand() instanceof EqualityOperation
}

predicate func_19(Variable vcaf_chunk_header_160, NotExpr target_19) {
		target_19.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_19.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="mChunkType"
		and target_19.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_19.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chan"
		and target_19.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
}

predicate func_20(Variable vcaf_chunk_header_160, ValueFieldAccess target_20) {
		target_20.getTarget().getName()="mChunkSize"
		and target_20.getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
}

predicate func_21(Parameter vconfig_153, Variable vcaf_chunk_header_160, LogicalOrExpr target_21) {
		target_21.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="12"
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="20"
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="num_channels"
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_153
}

predicate func_22(Parameter vconfig_153, Variable vdebug_logging_mode, IfStmt target_22) {
		target_22.getCondition().(VariableAccess).getTarget()=vdebug_logging_mode
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="float_norm_exp"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_153
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="127"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="data format: 32-bit %s-endian floating point"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(StringLiteral).getValue()="big"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(StringLiteral).getValue()="little"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="data format: %d-bit %s-endian integers stored in %d byte(s)"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="bits_per_sample"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_153
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(StringLiteral).getValue()="big"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(StringLiteral).getValue()="little"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="bytes_per_sample"
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_153
}

predicate func_23(Variable vdebug_logging_mode, IfStmt target_23) {
		target_23.getCondition().(VariableAccess).getTarget()=vdebug_logging_mode
		and target_23.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_23.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="chan %d --> %d"
		and target_23.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_23.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="mChannelLabel"
}

predicate func_24(Variable vcaf_channel_layout_277, ExprStmt target_24) {
		target_24.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcaf_channel_layout_277
}

predicate func_25(Variable vcaf_channel_layout_277, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("WavpackBigEndianToNative")
		and target_25.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_25.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="LLL"
}

predicate func_26(Variable vbcount_155, Variable vcaf_chunk_header_160, Parameter vinfile_153, LogicalOrExpr target_26) {
		target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="32"
		and target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfile_153
		and target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_26.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbcount_155
		and target_26.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbcount_155
		and target_26.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_26.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
}

predicate func_27(Variable vbcount_155, Parameter vinfile_153, LogicalOrExpr target_27) {
		target_27.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_27.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfile_153
		and target_27.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="4"
		and target_27.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbcount_155
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbcount_155
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getValue()="4"
}

predicate func_28(Parameter vinfilename_153, ExprStmt target_28) {
		target_28.getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_28.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is an unsupported .CAF format!"
		and target_28.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_153
}

predicate func_29(Parameter vinfilename_153, ExprStmt target_29) {
		target_29.getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_29.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .CAF file!"
		and target_29.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_153
}

predicate func_30(Parameter vwpc_153, Parameter vconfig_153, Variable vcaf_chunk_header_160, Variable vcaf_channel_layout_277, LogicalAndExpr target_30) {
		target_30.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="qmode"
		and target_30.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_153
		and target_30.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_30.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("WavpackAddWrapper")
		and target_30.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwpc_153
		and target_30.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcaf_channel_layout_277
		and target_30.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="mChunkSize"
		and target_30.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
}

predicate func_31(Variable vcaf_chunk_header_160, NotExpr target_31) {
		target_31.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_31.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="mChunkType"
		and target_31.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_31.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="data"
		and target_31.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
}

predicate func_32(Variable vcaf_chunk_header_160, ValueFieldAccess target_32) {
		target_32.getTarget().getName()="mChunkSize"
		and target_32.getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
}

predicate func_33(Variable vcaf_chunk_header_160, ArrayExpr target_33) {
		target_33.getArrayBase().(ValueFieldAccess).getTarget().getName()="mChunkType"
		and target_33.getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcaf_chunk_header_160
		and target_33.getArrayOffset().(Literal).getValue()="0"
}

predicate func_34(Parameter vinfilename_153, ExprStmt target_34) {
		target_34.getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_34.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s has too many samples for WavPack!"
		and target_34.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_153
}

predicate func_35(Parameter vwpc_153, Parameter vconfig_153, Variable vbcount_155, Parameter vinfile_153, Variable vbytes_to_copy_498, Variable vbuff_499, LogicalOrExpr target_35) {
		target_35.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_35.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfile_153
		and target_35.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuff_499
		and target_35.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbytes_to_copy_498
		and target_35.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbcount_155
		and target_35.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbcount_155
		and target_35.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbytes_to_copy_498
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="qmode"
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_153
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("WavpackAddWrapper")
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwpc_153
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuff_499
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbytes_to_copy_498
}

from Function func, Parameter vwpc_153, Parameter vconfig_153, Variable vbcount_155, Variable vcaf_chunk_header_160, Parameter vinfile_153, Parameter vinfilename_153, Variable vdebug_logging_mode, Variable vcaf_channel_layout_277, Variable vbytes_to_copy_498, Variable vbuff_499, EqualityOperation target_9, IfStmt target_10, FunctionCall target_11, FunctionCall target_13, Initializer target_14, Initializer target_15, BlockStmt target_16, ValueFieldAccess target_17, LogicalOrExpr target_18, NotExpr target_19, ValueFieldAccess target_20, LogicalOrExpr target_21, IfStmt target_22, IfStmt target_23, ExprStmt target_24, ExprStmt target_25, LogicalOrExpr target_26, LogicalOrExpr target_27, ExprStmt target_28, ExprStmt target_29, LogicalAndExpr target_30, NotExpr target_31, ValueFieldAccess target_32, ArrayExpr target_33, ExprStmt target_34, LogicalOrExpr target_35
where
not func_1(vbcount_155, vcaf_chunk_header_160, vinfile_153, vcaf_channel_layout_277, target_16, target_17, target_18)
and not func_2(target_18, func)
and not func_3(target_18, func)
and not func_4(vcaf_chunk_header_160, vdebug_logging_mode, target_19, target_20, target_21, target_22, target_23)
and not func_5(vcaf_channel_layout_277, target_19, target_24, target_25)
and not func_6(vbcount_155, vcaf_chunk_header_160, vinfile_153, vinfilename_153, vcaf_channel_layout_277, target_19, target_26, target_18, target_27, target_28, target_29, target_30)
and not func_7(vcaf_chunk_header_160, vinfilename_153, target_31, target_32, target_33, target_34)
and not func_8(vbuff_499, target_31, target_35)
and func_9(vbcount_155, vcaf_chunk_header_160, vinfile_153, vcaf_channel_layout_277, target_16, target_9)
and func_10(vwpc_153, vconfig_153, vcaf_chunk_header_160, vcaf_channel_layout_277, target_18, target_10)
and func_11(vcaf_chunk_header_160, target_11)
and func_13(vbytes_to_copy_498, target_13)
and func_14(func, target_14)
and func_15(func, target_15)
and func_16(vinfilename_153, vcaf_channel_layout_277, target_16)
and func_17(vcaf_chunk_header_160, target_17)
and func_18(vbcount_155, vcaf_chunk_header_160, vinfile_153, vcaf_channel_layout_277, target_18)
and func_19(vcaf_chunk_header_160, target_19)
and func_20(vcaf_chunk_header_160, target_20)
and func_21(vconfig_153, vcaf_chunk_header_160, target_21)
and func_22(vconfig_153, vdebug_logging_mode, target_22)
and func_23(vdebug_logging_mode, target_23)
and func_24(vcaf_channel_layout_277, target_24)
and func_25(vcaf_channel_layout_277, target_25)
and func_26(vbcount_155, vcaf_chunk_header_160, vinfile_153, target_26)
and func_27(vbcount_155, vinfile_153, target_27)
and func_28(vinfilename_153, target_28)
and func_29(vinfilename_153, target_29)
and func_30(vwpc_153, vconfig_153, vcaf_chunk_header_160, vcaf_channel_layout_277, target_30)
and func_31(vcaf_chunk_header_160, target_31)
and func_32(vcaf_chunk_header_160, target_32)
and func_33(vcaf_chunk_header_160, target_33)
and func_34(vinfilename_153, target_34)
and func_35(vwpc_153, vconfig_153, vbcount_155, vinfile_153, vbytes_to_copy_498, vbuff_499, target_35)
and vwpc_153.getType().hasName("WavpackContext *")
and vconfig_153.getType().hasName("WavpackConfig *")
and vbcount_155.getType().hasName("uint32_t")
and vcaf_chunk_header_160.getType().hasName("CAFChunkHeader")
and vinfile_153.getType().hasName("FILE *")
and vinfilename_153.getType().hasName("char *")
and vdebug_logging_mode.getType().hasName("int")
and vcaf_channel_layout_277.getType().hasName("CAFChannelLayout *")
and vbytes_to_copy_498.getType().hasName("int")
and vbuff_499.getType().hasName("char *")
and vwpc_153.getParentScope+() = func
and vconfig_153.getParentScope+() = func
and vbcount_155.getParentScope+() = func
and vcaf_chunk_header_160.getParentScope+() = func
and vinfile_153.getParentScope+() = func
and vinfilename_153.getParentScope+() = func
and not vdebug_logging_mode.getParentScope+() = func
and vcaf_channel_layout_277.getParentScope+() = func
and vbytes_to_copy_498.getParentScope+() = func
and vbuff_499.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
