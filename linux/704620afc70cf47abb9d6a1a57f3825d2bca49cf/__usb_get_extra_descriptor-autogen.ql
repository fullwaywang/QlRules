/**
 * @name linux-704620afc70cf47abb9d6a1a57f3825d2bca49cf-__usb_get_extra_descriptor
 * @id cpp/linux/704620afc70cf47abb9d6a1a57f3825d2bca49cf/--usb-get-extra-descriptor
 * @description linux-704620afc70cf47abb9d6a1a57f3825d2bca49cf-__usb_get_extra_descriptor NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vheader_837, Variable vusbcore_name, Parameter vsize_834) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="bLength"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_837
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_834
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3%s: bogus descriptor, type %d length %d\n"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vusbcore_name
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="bDescriptorType"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_837
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="bLength"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_837
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_1(Parameter vptr_835, Variable vheader_837) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="bLength"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_837
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_835
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vheader_837
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_2(Variable vheader_837, Variable vusbcore_name) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="bLength"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_837
		and target_2.getGreaterOperand().(Literal).getValue()="2"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3%s: bogus descriptor, type %d length %d\n"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vusbcore_name
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="bDescriptorType"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_837
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="bLength"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_837
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_3(Parameter vptr_835, Variable vheader_837, Parameter vtype_835) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="bDescriptorType"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheader_837
		and target_3.getAnOperand().(VariableAccess).getTarget()=vtype_835
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_835
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vheader_837
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_4(Variable vheader_837, Parameter vbuffer_834) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vheader_837
		and target_4.getRValue().(VariableAccess).getTarget()=vbuffer_834)
}

predicate func_5(Variable vheader_837) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="bLength"
		and target_5.getQualifier().(VariableAccess).getTarget()=vheader_837)
}

predicate func_6(Parameter vsize_834) {
	exists(RelationalOperation target_6 |
		 (target_6 instanceof GEExpr or target_6 instanceof LEExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vsize_834
		and target_6.getLesserOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_6.getLesserOperand().(SizeofTypeOperator).getValue()="2")
}

from Function func, Parameter vptr_835, Variable vheader_837, Variable vusbcore_name, Parameter vsize_834, Parameter vtype_835, Parameter vbuffer_834
where
not func_0(vheader_837, vusbcore_name, vsize_834)
and not func_1(vptr_835, vheader_837)
and func_2(vheader_837, vusbcore_name)
and func_3(vptr_835, vheader_837, vtype_835)
and vptr_835.getType().hasName("void **")
and vheader_837.getType().hasName("usb_descriptor_header *")
and func_4(vheader_837, vbuffer_834)
and func_5(vheader_837)
and vusbcore_name.getType().hasName("const char *")
and vsize_834.getType().hasName("unsigned int")
and func_6(vsize_834)
and vtype_835.getType().hasName("unsigned char")
and vbuffer_834.getType().hasName("char *")
and vptr_835.getParentScope+() = func
and vheader_837.getParentScope+() = func
and not vusbcore_name.getParentScope+() = func
and vsize_834.getParentScope+() = func
and vtype_835.getParentScope+() = func
and vbuffer_834.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
