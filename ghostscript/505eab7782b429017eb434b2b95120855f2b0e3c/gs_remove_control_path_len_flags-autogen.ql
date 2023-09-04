/**
 * @name ghostscript-505eab7782b429017eb434b2b95120855f2b0e3c-gs_remove_control_path_len_flags
 * @id cpp/ghostscript/505eab7782b429017eb434b2b95120855f2b0e3c/gs-remove-control-path-len-flags
 * @description ghostscript-505eab7782b429017eb434b2b95120855f2b0e3c-base/gslibctx.c-gs_remove_control_path_len_flags CVE-2023-36664
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="gp_validate_path"
		and not target_0.getValue()="gs_remove_control_path_len"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vpath_807, Parameter vlen_807, Variable vcore_811, Variable vbuffer_812, Variable vrlen_813, LogicalOrExpr target_10, EqualityOperation target_11, ExprStmt target_9, EqualityOperation target_12, EqualityOperation target_13, AddressOfExpr target_14, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_807
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="5"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_807
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%pipe"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_812
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getExpr() instanceof PointerDereferenceExpr
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_811
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_807
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(StringLiteral).getValue()="gs_remove_control_path_len"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_812
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_812
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpath_807
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_807
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_812
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_807
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrlen_813
		and target_1.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_807
		and target_1.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_812
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_bytes"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_811
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vrlen_813
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(StringLiteral).getValue()="gs_remove_control_path_len"
		and target_1.getElse().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_1.getElse().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_1.getElse().(BlockStmt).getStmt(4) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vcore_811, EqualityOperation target_12) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="memory"
		and target_3.getQualifier().(VariableAccess).getTarget()=vcore_811
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_4(Variable vcore_811, PointerDereferenceExpr target_4) {
		target_4.getOperand().(ValueFieldAccess).getTarget().getName()="alloc_bytes"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_811
}

*/
predicate func_5(Variable vcore_811, Variable vrlen_813, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="memory"
		and target_5.getQualifier().(VariableAccess).getTarget()=vcore_811
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_bytes"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_811
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vrlen_813
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(2) instanceof StringLiteral
}

predicate func_6(Variable vbuffer_812, Function func, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_812
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vpath_807, Parameter vlen_807, Variable vbuffer_812, Variable vrlen_813, Function func, IfStmt target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("gp_file_name_reduce")
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_807
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_807
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffer_812
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrlen_813
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vbuffer_812, Variable vrlen_813, Function func, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_812
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vrlen_813
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Parameter vlen_807, Variable vrlen_813, Function func, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrlen_813
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_807
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Parameter vpath_807, Parameter vlen_807, LogicalOrExpr target_10) {
		target_10.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpath_807
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_807
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_11(Parameter vpath_807, Parameter vlen_807, Variable vbuffer_812, Variable vrlen_813, EqualityOperation target_11) {
		target_11.getAnOperand().(FunctionCall).getTarget().hasName("gp_file_name_reduce")
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_807
		and target_11.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_807
		and target_11.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffer_812
		and target_11.getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrlen_813
}

predicate func_12(Variable vcore_811, EqualityOperation target_12) {
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_811
		and target_12.getAnOperand().(Literal).getValue()="0"
}

predicate func_13(Variable vbuffer_812, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vbuffer_812
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vrlen_813, AddressOfExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vrlen_813
}

from Function func, Parameter vpath_807, Parameter vlen_807, Variable vcore_811, Variable vbuffer_812, Variable vrlen_813, StringLiteral target_0, PointerFieldAccess target_5, IfStmt target_6, IfStmt target_7, ExprStmt target_8, ExprStmt target_9, LogicalOrExpr target_10, EqualityOperation target_11, EqualityOperation target_12, EqualityOperation target_13, AddressOfExpr target_14
where
func_0(func, target_0)
and not func_1(vpath_807, vlen_807, vcore_811, vbuffer_812, vrlen_813, target_10, target_11, target_9, target_12, target_13, target_14, func)
and func_5(vcore_811, vrlen_813, target_5)
and func_6(vbuffer_812, func, target_6)
and func_7(vpath_807, vlen_807, vbuffer_812, vrlen_813, func, target_7)
and func_8(vbuffer_812, vrlen_813, func, target_8)
and func_9(vlen_807, vrlen_813, func, target_9)
and func_10(vpath_807, vlen_807, target_10)
and func_11(vpath_807, vlen_807, vbuffer_812, vrlen_813, target_11)
and func_12(vcore_811, target_12)
and func_13(vbuffer_812, target_13)
and func_14(vrlen_813, target_14)
and vpath_807.getType().hasName("const char *")
and vlen_807.getType().hasName("size_t")
and vcore_811.getType().hasName("gs_lib_ctx_core_t *")
and vbuffer_812.getType().hasName("char *")
and vrlen_813.getType().hasName("uint")
and vpath_807.getFunction() = func
and vlen_807.getFunction() = func
and vcore_811.(LocalVariable).getFunction() = func
and vbuffer_812.(LocalVariable).getFunction() = func
and vrlen_813.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()