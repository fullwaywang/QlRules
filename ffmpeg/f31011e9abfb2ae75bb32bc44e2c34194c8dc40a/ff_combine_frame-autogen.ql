/**
 * @name ffmpeg-f31011e9abfb2ae75bb32bc44e2c34194c8dc40a-ff_combine_frame
 * @id cpp/ffmpeg/f31011e9abfb2ae75bb32bc44e2c34194c8dc40a/ff-combine-frame
 * @description ffmpeg-f31011e9abfb2ae75bb32bc44e2c34194c8dc40a-libavcodec/parser.c-ff_combine_frame CVE-2013-7023
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpc_216, NotExpr target_4, AddExpr target_5, ExprStmt target_6) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_216
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpc_216, NotExpr target_7, AddExpr target_8, ExprStmt target_9) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="overread_index"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_216
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_216
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(NotExpr target_4, Function func, ReturnStmt target_2) {
		target_2.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_2.getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func
}

predicate func_3(NotExpr target_7, Function func, ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_3.getParent().(IfStmt).getCondition()=target_7
		and target_3.getEnclosingFunction() = func
}

predicate func_4(NotExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget().getType().hasName("void *")
}

predicate func_5(Parameter vpc_216, AddExpr target_5) {
		target_5.getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int *")
		and target_5.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="index"
		and target_5.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_216
		and target_5.getAnOperand().(Literal).getValue()="16"
}

predicate func_6(Parameter vpc_216, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_216
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("void *")
}

predicate func_7(NotExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget().getType().hasName("void *")
}

predicate func_8(Parameter vpc_216, AddExpr target_8) {
		target_8.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="index"
		and target_8.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_216
		and target_8.getAnOperand().(Literal).getValue()="16"
}

predicate func_9(Parameter vpc_216, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_216
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("void *")
}

from Function func, Parameter vpc_216, ReturnStmt target_2, ReturnStmt target_3, NotExpr target_4, AddExpr target_5, ExprStmt target_6, NotExpr target_7, AddExpr target_8, ExprStmt target_9
where
not func_0(vpc_216, target_4, target_5, target_6)
and not func_1(vpc_216, target_7, target_8, target_9)
and func_2(target_4, func, target_2)
and func_3(target_7, func, target_3)
and func_4(target_4)
and func_5(vpc_216, target_5)
and func_6(vpc_216, target_6)
and func_7(target_7)
and func_8(vpc_216, target_8)
and func_9(vpc_216, target_9)
and vpc_216.getType().hasName("ParseContext *")
and vpc_216.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
