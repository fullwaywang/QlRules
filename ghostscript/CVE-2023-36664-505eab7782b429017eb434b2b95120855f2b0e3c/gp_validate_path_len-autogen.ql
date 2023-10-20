/**
 * @name ghostscript-505eab7782b429017eb434b2b95120855f2b0e3c-gp_validate_path_len
 * @id cpp/ghostscript/505eab7782b429017eb434b2b95120855f2b0e3c/gp-validate-path-len
 * @description ghostscript-505eab7782b429017eb434b2b95120855f2b0e3c-base/gpmisc.c-gp_validate_path_len CVE-2023-36664
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpath_1041, Parameter vlen_1042, Variable vbuffer_1045, Variable vbufferfull_1045, Variable vrlen_1046, PointerArithmeticOperation target_7, EqualityOperation target_8, LogicalAndExpr target_9, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_1042
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="5"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_1041
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%pipe"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbufferfull_1045
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_1045
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="thread_safe_memory"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ExprCall).getArgument(2).(StringLiteral).getValue()="gp_validate_path"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_1045
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_1045
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpath_1041
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_1042
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_1045
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_1042
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrlen_1046
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_1042
		and target_0.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getElse().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getElse().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_0.getElse().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_0.getElse().(BlockStmt).getStmt(4) instanceof IfStmt
		and target_0.getElse().(BlockStmt).getStmt(5) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_7.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlen_1042, Variable vrlen_1046, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrlen_1046
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_1042
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vmem_1040, Variable vbufferfull_1045, Variable vrlen_1046, Variable vprefix_len_1052, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbufferfull_1045
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_bytes"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="thread_safe_memory"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="thread_safe_memory"
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmem_1040
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrlen_1046
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vprefix_len_1052
		and target_2.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(StringLiteral).getValue()="gp_validate_path"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vbufferfull_1045, Function func, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbufferfull_1045
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vbuffer_1045, Variable vbufferfull_1045, Variable vprefix_len_1052, Function func, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_1045
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbufferfull_1045
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vprefix_len_1052
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vpath_1041, Parameter vlen_1042, Variable vbuffer_1045, Variable vrlen_1046, Function func, IfStmt target_5) {
		target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("gp_file_name_reduce")
		and target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_1041
		and target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_1042
		and target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffer_1045
		and target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrlen_1046
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vbuffer_1045, Variable vrlen_1046, Function func, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_1045
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vrlen_1046
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vpath_1041, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vpath_1041
		and target_7.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_8(Parameter vpath_1041, Parameter vlen_1042, Variable vbuffer_1045, Variable vrlen_1046, EqualityOperation target_8) {
		target_8.getAnOperand().(FunctionCall).getTarget().hasName("gp_file_name_reduce")
		and target_8.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_1041
		and target_8.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_1042
		and target_8.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffer_1045
		and target_8.getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrlen_1046
}

predicate func_9(Parameter vpath_1041, Parameter vlen_1042, Variable vprefix_len_1052, LogicalAndExpr target_9) {
		target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_1042
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vprefix_len_1052
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_1041
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_9.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpath_1041
		and target_9.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_9.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vmem_1040, Parameter vpath_1041, Parameter vlen_1042, Variable vbuffer_1045, Variable vbufferfull_1045, Variable vrlen_1046, Variable vprefix_len_1052, ExprStmt target_1, ExprStmt target_2, IfStmt target_3, ExprStmt target_4, IfStmt target_5, ExprStmt target_6, PointerArithmeticOperation target_7, EqualityOperation target_8, LogicalAndExpr target_9
where
not func_0(vpath_1041, vlen_1042, vbuffer_1045, vbufferfull_1045, vrlen_1046, target_7, target_8, target_9, target_1, func)
and func_1(vlen_1042, vrlen_1046, func, target_1)
and func_2(vmem_1040, vbufferfull_1045, vrlen_1046, vprefix_len_1052, func, target_2)
and func_3(vbufferfull_1045, func, target_3)
and func_4(vbuffer_1045, vbufferfull_1045, vprefix_len_1052, func, target_4)
and func_5(vpath_1041, vlen_1042, vbuffer_1045, vrlen_1046, func, target_5)
and func_6(vbuffer_1045, vrlen_1046, func, target_6)
and func_7(vpath_1041, target_7)
and func_8(vpath_1041, vlen_1042, vbuffer_1045, vrlen_1046, target_8)
and func_9(vpath_1041, vlen_1042, vprefix_len_1052, target_9)
and vmem_1040.getType().hasName("const gs_memory_t *")
and vpath_1041.getType().hasName("const char *")
and vlen_1042.getType().hasName("const uint")
and vbuffer_1045.getType().hasName("char *")
and vbufferfull_1045.getType().hasName("char *")
and vrlen_1046.getType().hasName("uint")
and vprefix_len_1052.getType().hasName("int")
and vmem_1040.getFunction() = func
and vpath_1041.getFunction() = func
and vlen_1042.getFunction() = func
and vbuffer_1045.(LocalVariable).getFunction() = func
and vbufferfull_1045.(LocalVariable).getFunction() = func
and vrlen_1046.(LocalVariable).getFunction() = func
and vprefix_len_1052.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
