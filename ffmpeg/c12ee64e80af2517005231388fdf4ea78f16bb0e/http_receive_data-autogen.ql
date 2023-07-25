/**
 * @name ffmpeg-c12ee64e80af2517005231388fdf4ea78f16bb0e-http_receive_data
 * @id cpp/ffmpeg/c12ee64e80af2517005231388fdf4ea78f16bb0e/http-receive-data
 * @description ffmpeg-c12ee64e80af2517005231388fdf4ea78f16bb0e-ffserver.c-http_receive_data CVE-2016-10192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_2683, GotoStmt target_12, ExprStmt target_13, ExprStmt target_14) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_12
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vc_2683, RelationalOperation target_15, ExprStmt target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vc_2683, Variable vlen_2686, EqualityOperation target_16, ConditionalExpr target_17, ExprStmt target_5) {
	exists(DoStmt target_2 |
		target_2.getCondition() instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_2686
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="len <= c->chunk_size"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_17.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vc_2683, GotoStmt target_12, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="chunk_size"
		and target_3.getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_3.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_12
}

predicate func_4(Parameter vc_2683, Variable vlen_2686, RelationalOperation target_15, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_2686
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("recv")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fd"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buffer_ptr"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="buffer_end"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="buffer_ptr"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="buffer_end"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="buffer_ptr"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_5(Parameter vc_2683, Variable vlen_2686, EqualityOperation target_16, ExprStmt target_5) {
		target_5.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_5.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_5.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vlen_2686
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_6(Parameter vc_2683, Variable vlen_2686, EqualityOperation target_16, ExprStmt target_6) {
		target_6.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer_ptr"
		and target_6.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vlen_2686
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_7(Parameter vc_2683, Variable vlen_2686, EqualityOperation target_16, ExprStmt target_7) {
		target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data_count"
		and target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_7.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vlen_2686
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_8(Parameter vc_2683, EqualityOperation target_16, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("update_datarate")
		and target_8.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="datarate"
		and target_8.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data_count"
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_10(RelationalOperation target_18, Function func, GotoStmt target_10) {
		target_10.toString() = "goto ..."
		and target_10.getName() ="fail"
		and target_10.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_18
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Parameter vc_2683, GotoStmt target_12, EqualityOperation target_11) {
		target_11.getAnOperand().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_11.getAnOperand() instanceof Literal
		and target_11.getParent().(IfStmt).getThen()=target_12
}

predicate func_12(GotoStmt target_12) {
		target_12.toString() = "goto ..."
		and target_12.getName() ="fail"
}

predicate func_13(Parameter vc_2683, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strtol")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="16"
}

predicate func_14(Parameter vc_2683, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer_ptr"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
}

predicate func_15(Parameter vc_2683, RelationalOperation target_15) {
		 (target_15 instanceof GTExpr or target_15 instanceof LTExpr)
		and target_15.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="buffer_end"
		and target_15.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_15.getLesserOperand().(PointerFieldAccess).getTarget().getName()="buffer_ptr"
		and target_15.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
}

predicate func_16(Variable vlen_2686, EqualityOperation target_16) {
		target_16.getAnOperand().(VariableAccess).getTarget()=vlen_2686
		and target_16.getAnOperand().(Literal).getValue()="0"
}

predicate func_17(Parameter vc_2683, ConditionalExpr target_17) {
		target_17.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_17.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="buffer_end"
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="buffer_ptr"
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_17.getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="buffer_end"
		and target_17.getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_17.getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="buffer_ptr"
		and target_17.getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
		and target_17.getElse().(PointerFieldAccess).getTarget().getName()="chunk_size"
		and target_17.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2683
}

predicate func_18(Variable vlen_2686, RelationalOperation target_18) {
		 (target_18 instanceof GTExpr or target_18 instanceof LTExpr)
		and target_18.getLesserOperand().(VariableAccess).getTarget()=vlen_2686
		and target_18.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Parameter vc_2683, Variable vlen_2686, PointerFieldAccess target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, GotoStmt target_10, EqualityOperation target_11, GotoStmt target_12, ExprStmt target_13, ExprStmt target_14, RelationalOperation target_15, EqualityOperation target_16, ConditionalExpr target_17, RelationalOperation target_18
where
not func_0(vc_2683, target_12, target_13, target_14)
and not func_1(vc_2683, target_15, target_4)
and not func_2(vc_2683, vlen_2686, target_16, target_17, target_5)
and func_3(vc_2683, target_12, target_3)
and func_4(vc_2683, vlen_2686, target_15, target_4)
and func_5(vc_2683, vlen_2686, target_16, target_5)
and func_6(vc_2683, vlen_2686, target_16, target_6)
and func_7(vc_2683, vlen_2686, target_16, target_7)
and func_8(vc_2683, target_16, target_8)
and func_10(target_18, func, target_10)
and func_11(vc_2683, target_12, target_11)
and func_12(target_12)
and func_13(vc_2683, target_13)
and func_14(vc_2683, target_14)
and func_15(vc_2683, target_15)
and func_16(vlen_2686, target_16)
and func_17(vc_2683, target_17)
and func_18(vlen_2686, target_18)
and vc_2683.getType().hasName("HTTPContext *")
and vlen_2686.getType().hasName("int")
and vc_2683.getParentScope+() = func
and vlen_2686.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
